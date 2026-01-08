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
 * - identities:id -> JSON string
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
   * Salva uma identidade no store
   */
  async setIdentity(id: string, identity: Identity): Promise<void> {
    const key = `identity:${id}`;
    const value = JSON.stringify(identity);
    
    // Calcula TTL em segundos
    const ttlMs = identity.expiresAt - Date.now();
    const ttlSeconds = Math.max(1, Math.floor(ttlMs / 1000));
    
    await this.redis.set(key, value, { ex: ttlSeconds });
  }

  /**
   * Busca uma identidade por ID
   */
  async getIdentity(id: string): Promise<Identity | null> {
    const key = `identity:${id}`;
    const value = await this.redis.get(key);

    if (!value) return null;

    // Fallback: se não for string, retorna null (dados corrompidos)
    if (typeof value !== 'string') {
      console.error(`[DB] Invalid data type for ${id}: ${typeof value}`);
      await this.redis.del(key); // Remove dados corrompidos
      return null;
    }

    try {
      return JSON.parse(value as string) as Identity;
    } catch (error) {
      console.error(`[DB] Failed to parse identity ${id}:`, error);
      await this.redis.del(key); // Remove dados corrompidos
      return null;
    }
  }
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
      .filter(v => v !== null && typeof v === 'string')
      .map(v => {
        try {
          return JSON.parse(v as string) as Identity;
        } catch (error) {
          console.error(`[DB] Failed to parse identity from list:`, error);
          return null;
        }
      .filter(v => v !== null) as Identity[];
  }
  }

  /**
   * Tracking de tentativas por IP
   */
  async trackIP(ip: string): Promise<number> {
    const key = `ipTracking:${ip}`;
    const value = await this.redis.get(key);
    const now = Date.now();

    if (value) {
      const existing = JSON.parse(value as string);
      
      // Reseta contador se última tentativa foi há mais de 5 minutos
      if (now - existing.lastAttempt > 300000) {
        const newData = { attempts: 1, lastAttempt: now };
        await this.redis.set(key, JSON.stringify(newData), { ex: 300 });
        return 1;
      }
      
      existing.attempts++;
      existing.lastAttempt = now;
      await this.redis.set(key, JSON.stringify(existing), { ex: 300 });
      return existing.attempts;
    }

    const newData = { attempts: 1, lastAttempt: now };
    await this.redis.set(key, JSON.stringify(newData), { ex: 300 });
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
    const key = `apiKey:${hashedKey}`;
    const value = JSON.stringify(apiKey);
    await this.redis.set(key, value);
  }

  async getApiKey(hashedKey: string): Promise<any | null> {
    const key = `apiKey:${hashedKey}`;
    const value = await this.redis.get(key);
    
    if (!value) return null;
    
    return JSON.parse(value as string);
  }

  async listApiKeys(): Promise<any[]> {
    const keys = await this.redis.keys('apiKey:*');
    if (keys.length === 0) return [];
    
    const values = await this.redis.mget(...keys);
    return values
      .filter(v => v !== null)
      .map(v => JSON.parse(v as string));
  }

  async deleteApiKey(hashedKey: string): Promise<boolean> {
    const key = `apiKey:${hashedKey}`;
    const result = await this.redis.del(key);
    return result > 0;
  }

  /**
   * Limpa identidades expiradas (garbage collector)
   * No Redis com TTL, isso é automático, mas mantemos para compatibilidade
   */
  async cleanExpired(): Promise<number> {
    // Redis já limpa automaticamente com TTL
    // Mas podemos verificar e limpar manualmente se necessário
    const keys = await this.redis.keys('identity:*');
    let cleaned = 0;

    for (const key of keys) {
      const value = await this.redis.get(key);
      if (value) {
        const identity = JSON.parse(value as string) as Identity;
        if (!identity.isAlive) {
          await this.redis.del(key);
          cleaned++;
        }
      }
    }

    return cleaned;
  }
}

// Singleton instance
export const db = new RedisKVStore();

// Auto-cleanup a cada 5 minutos (opcional com Redis TTL)
setInterval(() => {
  db.cleanExpired().then(count => {
    if (count > 0) {
      console.log(`[DB] Cleaned ${count} expired identities`);
    }
  }).catch(err => {
    console.error('[DB] Cleanup error:', err);
  });
}, 300000);