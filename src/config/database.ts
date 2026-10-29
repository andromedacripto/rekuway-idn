// Carrega dotenv ANTES de tudo
import dotenv from 'dotenv';
dotenv.config();

import { Redis } from '@upstash/redis';
import { Identity } from '../models/Identity';

interface IPTrackingData {
  attempts: number;
  lastAttempt: number;
}

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

  /** SCAN em lotes: KEYS é O(N) e bloqueia o Redis em escala. */
  private async scanKeys(pattern: string): Promise<string[]> {
    const found = new Set<string>();
    let cursor: string | number = 0;
    let guard = 0;
    do {
      const [next, batch]: [string, string[]] = await this.redis.scan(cursor, {
        match: pattern,
        count: 500,
      });
      batch.forEach((k) => found.add(k));
      cursor = next;
      guard++;
    } while (String(cursor) !== '0' && guard < 10_000);
    return Array.from(found);
  }

  async set(key: string, value: unknown, ttlSeconds?: number): Promise<boolean> {
    try {
      const serialized = JSON.stringify(value);

      if (ttlSeconds && ttlSeconds > 0) {
        await this.redis.set(key, serialized, { ex: ttlSeconds });
      } else {
        await this.redis.set(key, serialized);
      }

      return true;
    } catch (error) {
      console.error('[DB] Error setting key:', key, error);
      return false;
    }
  }

  async get(key: string): Promise<unknown | null> {
    try {
      const value = await this.redis.get(key);

      if (!value) return null;

      if (typeof value === 'object' && value !== null) return value;

      if (typeof value === 'string') {
        try {
          return JSON.parse(value);
        } catch {
          return value;
        }
      }

      return value;
    } catch (error) {
      console.error('[DB] Error getting key:', key, error);
      return null;
    }
  }

  async setIdentity(id: string, identity: Identity): Promise<void> {
    const key = `identity:${id}`;
    const ttlMs = identity.expiresAt - Date.now();
    const ttlSeconds = Math.max(1, Math.floor(ttlMs / 1000));
    await this.set(key, identity, ttlSeconds);
  }

  async getIdentity(id: string): Promise<Identity | null> {
    const key = `identity:${id}`;
    const value = (await this.get(key)) as Record<string, unknown> | null;

    if (!value) return null;

    if (!value.id || !value.publicKey) {
      console.error(`[DB] Invalid identity structure for ${id}`);
      await this.redis.del(key);
      return null;
    }

    if (typeof value.totalAttempts === 'undefined') {
      value.totalAttempts = value.attempts || 0;
    }
    if (typeof value.regenerationCount === 'undefined') {
      value.regenerationCount = 0;
    }
    if (typeof value.attemptsAfterRegenerate === 'undefined') {
      value.attemptsAfterRegenerate = 0;
    }

    return value as unknown as Identity;
  }

  async deleteIdentity(id: string): Promise<boolean> {
    const key = `identity:${id}`;
    const result = await this.redis.del(key);
    return result > 0;
  }

  async listIdentities(): Promise<Identity[]> {
    const keys = await this.scanKeys('identity:*');
    if (keys.length === 0) return [];

    const values = await this.redis.mget(...keys);

    return values
      .filter((v) => v !== null)
      .map((v) => {
        if (typeof v === 'object' && v !== null) return v as Identity;
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
      .filter((v) => v !== null) as Identity[];
  }

  async trackIP(ip: string): Promise<number> {
    const key = `ipTracking:${ip}`;
    const value = (await this.get(key)) as IPTrackingData | null;
    const now = Date.now();

    if (value) {
      if (now - value.lastAttempt > 300000) {
        await this.set(key, { attempts: 1, lastAttempt: now }, 300);
        return 1;
      }
      value.attempts++;
      value.lastAttempt = now;
      await this.set(key, value, 300);
      return value.attempts;
    }

    await this.set(key, { attempts: 1, lastAttempt: now }, 300);
    return 1;
  }

  async clearIPTracking(ip: string): Promise<void> {
    const key = `ipTracking:${ip}`;
    await this.redis.del(key);
  }

  async setApiKey(hashedKey: string, apiKey: Record<string, unknown>): Promise<void> {
    const key = `apikey:${hashedKey}`;
    await this.set(key, apiKey);
  }

  async getApiKey(hashedKey: string): Promise<Record<string, unknown> | null> {
    const key = `apikey:${hashedKey}`;
    return (await this.get(key)) as Record<string, unknown> | null;
  }

  async listApiKeys(): Promise<Record<string, unknown>[]> {
    const keys = await this.scanKeys('apikey:*');
    if (keys.length === 0) return [];

    const values = await this.redis.mget(...keys);
    return values
      .filter((v) => v !== null)
      .map((v) => (typeof v === 'string' ? JSON.parse(v) : v)) as Record<string, unknown>[];
  }

  async deleteApiKey(hashedKey: string): Promise<boolean> {
    const key = `apikey:${hashedKey}`;
    const result = await this.redis.del(key);
    return result > 0;
  }

  async cleanExpired(): Promise<number> {
    const keys = await this.scanKeys('identity:*');
    let cleaned = 0;

    for (const key of keys) {
      const value = (await this.get(key)) as Record<string, unknown> | null;
      if (value) {
        if (!value.isAlive || (value.expiresAt as number) < Date.now()) {
          await this.redis.del(key);
          cleaned++;
        }
      }
    }

    return cleaned;
  }

  async delete(key: string): Promise<boolean> {
    try {
      const result = await this.redis.del(key);
      return result > 0;
    } catch (error) {
      console.error('[DB] Error deleting key:', key, error);
      return false;
    }
  }

  async exists(key: string): Promise<boolean> {
    try {
      const result = await this.redis.exists(key);
      return result === 1;
    } catch (error) {
      console.error('[DB] Error checking existence of:', key, error);
      return false;
    }
  }

  async keys(pattern: string): Promise<string[]> {
    try {
      const keys = await this.scanKeys(pattern);
      return keys || [];
    } catch (error) {
      console.error('[DB] Error listing keys:', pattern, error);
      return [];
    }
  }
}

// Singleton instance
export const db = new RedisKVStore();

// Auto-cleanup a cada 5 minutos
setInterval(() => {
  db.cleanExpired()
    .then((count) => {
      if (count > 0) {
        console.log(`[DB] 🧹 Cleaned ${count} expired identities`);
      }
    })
    .catch((err) => {
      console.error('[DB] ❌ Cleanup error:', err);
    });
}, 300000);
