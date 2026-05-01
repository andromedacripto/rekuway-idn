// Carrega dotenv ANTES de tudo
import dotenv from 'dotenv';
dotenv.config();

import { Redis } from '@upstash/redis';
import { Identity } from '../models/Identity';

/**
 * Redis KV Store usando Upstash REST API
 * Funciona melhor com firewalls e não precisa de porta TCP
 * 
 * Estrutura:
 * - identity:id -> JSON string (ou objeto auto-parseado pelo Upstash)
 * - ipTracking:ip -> JSON string
 * - apiKeys:hashedKey -> JSON string
 */

class RedisKVStore {
  private redis: Redis;

  constructor() {
    const redisUrl = process.env.UPSTASH_REDIS_REST_URL;
    const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;
    
    if (!redisUrl || !redisToken) {
      console.error('❌ UPSTASH_REDIS_REST_URL or UPSTASH_REDIS_REST_TOKEN not found!');
      console.error('Configure essas variáveis no .env');
      throw new Error('❌ Upstash REST credentials not configured');
    }

    console.log('🔄 Connecting to Upstash Redis (REST API)...');

    this.redis = new Redis({
      url: redisUrl,
      token: redisToken,
    });

    console.log('✅ Connected to Redis (Upstash REST API)');
  }

  /**
   * 🔥 MÉTODO SET GENÉRICO (necessário para identityRoutes.ts)
   * Salva qualquer dado no Redis com TTL opcional
   */
  async set(key: string, value: any, ttlSeconds?: number): Promise<boolean> {
    try {
      const serialized = JSON.stringify(value);
      
      if (ttlSeconds && ttlSeconds > 0) {
        await this.redis.set(key, serialized, { ex: ttlSeconds });
      } else {
        await this.redis.set(key, serialized);
      }
      
      return true;
    } catch (error) {
      console.error(`[DB] Error setting key ${key}:`, error);
      return false;
    }
  }

  /**
   * 🔥 MÉTODO GET GENÉRICO
   * Busca qualquer dado do Redis
   */
  async get(key: string): Promise<any | null> {
    try {
      const value = await this.redis.get(key);
      
      if (!value) {
        return null;
      }

      // Upstash pode retornar objeto já parseado OU string
      if (typeof value === 'object' && value !== null) {
        return value;
      }

      if (typeof value === 'string') {
        try { return JSON.parse(value); } catch { return value; }
      }

      return value;
    } catch (error) {
      console.error(`[DB] Error getting key ${key}:`, error);
      return null;
    }
  }

  /**
   * Salva uma identidade no store
   * Usa set() genérico internamente
   */
  async setIdentity(id: string, identity: Identity): Promise<void> {
    const key = `identity:${id}`;
    
    // Calcula TTL em segundos
    const ttlMs = identity.expiresAt - Date.now();
    const ttlSeconds = Math.max(1, Math.floor(ttlMs / 1000));
    
    await this.set(key, identity, ttlSeconds);
  }

  /**
   * Busca uma identidade por ID
   * Usa get() genérico internamente
   */
  async getIdentity(id: string): Promise<Identity | null> {
    const key = `identity:${id}`;
    const value = await this.get(key);

    if (!value) {
      return null;
    }

    // Validação básica de estrutura
    if (!value.id || !value.publicKey) {
      console.error(`[DB] Invalid identity structure for ${id}`);
      await this.redis.del(key);
      return null;
    }

    // 🔥 INICIALIZA NOVOS CAMPOS SE NÃO EXISTIREM (retrocompatibilidade)
    if (typeof value.totalAttempts === 'undefined') {
      value.totalAttempts = value.attempts || 0;
    }
    if (typeof value.regenerationCount === 'undefined') {
      value.regenerationCount = 0;
    }
    if (typeof value.attemptsAfterRegenerate === 'undefined') {
      value.attemptsAfterRegenerate = 0;
    }

    return value as Identity;
  }

  /**
   * Deleta uma identidade (kill)
   */
  async deleteIdentity(id: string): Promise<boolean> {
    const key = `identity:${id}`;
    const result = await this.redis.del(key);
    return result > 0;
  }

  /**
   * Lista todas as identidades (útil pra debug)
   */
  async listIdentities(): Promise<Identity[]> {
    const keys = await this.redis.keys('identity:*');
    if (keys.length === 0) return [];
    
    const values = await this.redis.mget(...keys);
    
    return values
      .filter(v => v !== null)
      .map(v => {
        // Aceita objeto OU string
        if (typeof v === 'object' && v !== null) {
          return v as Identity;
        }
        
        if (typeof v === 'string') {
          try {
            return JSON.parse(v) as Identity;
          } catch (error) {
            console.error(`[DB] Failed to parse identity from list:`, error);
            return null;
          }
        }
        
        return null;
      })
      .filter(v => v !== null) as Identity[];
  }

  /**
   * Tracking de tentativas por IP
   */
  async trackIP(ip: string): Promise<number> {
    const key = `ipTracking:${ip}`;
    const value = await this.get(key);
    const now = Date.now();

    if (value) {
      // Reseta contador se última tentativa foi há mais de 5 minutos
      if (now - value.lastAttempt > 300000) {
        const newData = { attempts: 1, lastAttempt: now };
        await this.set(key, newData, 300);
        return 1;
      }
      
      value.attempts++;
      value.lastAttempt = now;
      await this.set(key, value, 300);
      return value.attempts;
    }

    const newData = { attempts: 1, lastAttempt: now };
    await this.set(key, newData, 300);
    return 1;
  }

  /**
   * Limpa tracking de um IP
   */
  async clearIPTracking(ip: string): Promise<void> {
    const key = `ipTracking:${ip}`;
    await this.redis.del(key);
  }

  /**
   * API Keys CRUD
   */
  async setApiKey(hashedKey: string, apiKey: any): Promise<void> {
    const key = `apikey:${hashedKey}`;
    await this.set(key, apiKey);
  }

  async getApiKey(hashedKey: string): Promise<any | null> {
    const key = `apikey:${hashedKey}`;
    return await this.get(key);
  }

  async listApiKeys(): Promise<any[]> {
    const keys = await this.redis.keys('apikey:*');
    if (keys.length === 0) return [];
    
    const values = await this.redis.mget(...keys);
    return values
      .filter(v => v !== null)
      .map(v => typeof v === 'string' ? JSON.parse(v) : v);
  }

  async deleteApiKey(hashedKey: string): Promise<boolean> {
    const key = `apikey:${hashedKey}`;
    const result = await this.redis.del(key);
    return result > 0;
  }

  /**
   * Limpa identidades expiradas (garbage collector)
   */
  async cleanExpired(): Promise<number> {
    const keys = await this.redis.keys('identity:*');
    let cleaned = 0;

    for (const key of keys) {
      const value = await this.get(key);
      if (value) {
        if (!value.isAlive || value.expiresAt < Date.now()) {
          await this.redis.del(key);
          cleaned++;
        }
      }
    }

    return cleaned;
  }

  /**
   * 🔥 MÉTODO DELETE GENÉRICO
   * Deleta qualquer chave
   */
  async delete(key: string): Promise<boolean> {
    try {
      const result = await this.redis.del(key);
      return result > 0;
    } catch (error) {
      console.error(`[DB] Error deleting key ${key}:`, error);
      return false;
    }
  }

  /**
   * 🔥 MÉTODO EXISTS
   * Verifica se chave existe
   */
  async exists(key: string): Promise<boolean> {
    try {
      const result = await this.redis.exists(key);
      return result === 1;
    } catch (error) {
      console.error(`[DB] Error checking existence of ${key}:`, error);
      return false;
    }
  }

  /**
   * 🔥 MÉTODO KEYS
   * Lista chaves por padrão
   */
  async keys(pattern: string): Promise<string[]> {
    try {
      const keys = await this.redis.keys(pattern);
      return keys || [];
    } catch (error) {
      console.error(`[DB] Error listing keys ${pattern}:`, error);
      return [];
    }
  }
}

// Singleton instance
export const db = new RedisKVStore();

// Auto-cleanup a cada 5 minutos
setInterval(() => {
  db.cleanExpired().then(count => {
    if (count > 0) {
      console.log(`[DB] 🧹 Cleaned ${count} expired identities`);
    }
  }).catch(err => {
    console.error('[DB] ❌ Cleanup error:', err);
  });
}, 300000);