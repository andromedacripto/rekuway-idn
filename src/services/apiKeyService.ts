import crypto from 'crypto';
import { db } from '../config/database';

/**
 * Interface para API Key
 */
export interface ApiKey {
  key: string;              // API key pública (rkwy_...)
  hashedKey: string;        // Hash da key (armazenado)
  name: string;             // Nome/descrição
  userId: string;           // ID do usuário/empresa
  tier: 'hobby' | 'startup' | 'business' | 'enterprise';
  
  // Rate limits por tier
  rateLimit: {
    identitiesPerMonth: number;
    requestsPerMinute: number;
  };
  
  // Tracking de uso
  usage: {
    identitiesCreated: number;
    requestsThisMinute: number;
    lastRequest: number;
    resetDate: number;  // Timestamp do próximo reset mensal
  };
  
  createdAt: number;
  isActive: boolean;
}

/**
 * Tiers de planos
 */
const TIERS = {
  hobby: {
    identitiesPerMonth: 100,
    requestsPerMinute: 10
  },
  startup: {
    identitiesPerMonth: 1000,
    requestsPerMinute: 100
  },
  business: {
    identitiesPerMonth: 10000,
    requestsPerMinute: 1000
  },
  enterprise: {
    identitiesPerMonth: -1, // ilimitado
    requestsPerMinute: -1   // ilimitado
  }
};

/**
 * Gera uma nova API key
 * Formato: rkwy_live_xxxxxxxxxxxxx (32 chars random)
 */
export function generateApiKey(): string {
  const randomPart = crypto.randomBytes(16).toString('hex');
  return `rkwy_live_${randomPart}`;
}

/**
 * Hash da API key para armazenamento seguro
 */
function hashApiKey(apiKey: string): string {
  return crypto.createHash('sha256').update(apiKey).digest('hex');
}

/**
 * Cria uma nova API key para um usuário
 */
export async function createApiKey(
  userId: string,
  name: string,
  tier: ApiKey['tier'] = 'hobby'
): Promise<{ apiKey: ApiKey; plainKey: string }> {
  const plainKey = generateApiKey();
  const hashedKey = hashApiKey(plainKey);
  
  const now = Date.now();
  const resetDate = now + (30 * 24 * 60 * 60 * 1000); // +30 dias
  
  const apiKey: ApiKey = {
    key: hashedKey, // Mostra só parte pra segurança
    hashedKey,
    name,
    userId,
    tier,
    rateLimit: TIERS[tier],
    usage: {
      identitiesCreated: 0,
      requestsThisMinute: 0,
      lastRequest: now,
      resetDate
    },
    createdAt: now,
    isActive: true
  };
  
  // Salva no banco
  await db.setApiKey(hashedKey, apiKey);
  
  console.log(`[API_KEY] Created for user ${userId} (tier: ${tier})`);
  
  return { apiKey, plainKey }; // Retorna plainKey APENAS na criação
}

/**
 * Valida uma API key e retorna os dados se válida
 */
export async function validateApiKey(apiKey: string): Promise<ApiKey | null> {
  if (!apiKey || !apiKey.startsWith('rkwy_live_')) {
    return null;
  }
  
  const hashedKey = hashApiKey(apiKey);
  const keyData = await db.getApiKey(hashedKey);
  
  if (!keyData || !keyData.isActive) {
    return null;
  }
  
  return keyData;
}

/**
 * Verifica rate limits e atualiza contadores
 */
export async function checkRateLimit(apiKey: ApiKey, isIdentityCreation: boolean = false): Promise<{
  allowed: boolean;
  reason?: string;
  limits: {
    identitiesRemaining: number;
    requestsPerMinute: number;
  };
}> {
  const now = Date.now();
  
  // Reset mensal
  if (now > apiKey.usage.resetDate) {
    apiKey.usage.identitiesCreated = 0;
    apiKey.usage.resetDate = now + (30 * 24 * 60 * 60 * 1000);
  }
  
  // Reset por minuto
  if (now - apiKey.usage.lastRequest > 60000) {
    apiKey.usage.requestsThisMinute = 0;
  }
  
  // Verifica limite de identidades (se for criação)
  if (isIdentityCreation) {
    const limit = apiKey.rateLimit.identitiesPerMonth;
    if (limit !== -1 && apiKey.usage.identitiesCreated >= limit) {
      return {
        allowed: false,
        reason: `Monthly limit of ${limit} identities exceeded. Upgrade your plan.`,
        limits: {
          identitiesRemaining: 0,
          requestsPerMinute: apiKey.rateLimit.requestsPerMinute
        }
      };
    }
  }
  
  // Verifica limite de requests por minuto
  const reqLimit = apiKey.rateLimit.requestsPerMinute;
  if (reqLimit !== -1 && apiKey.usage.requestsThisMinute >= reqLimit) {
    return {
      allowed: false,
      reason: `Rate limit of ${reqLimit} requests per minute exceeded.`,
      limits: {
        identitiesRemaining: apiKey.rateLimit.identitiesPerMonth - apiKey.usage.identitiesCreated,
        requestsPerMinute: 0
      }
    };
  }
  
  // Incrementa contadores
  apiKey.usage.requestsThisMinute++;
  apiKey.usage.lastRequest = now;
  
  if (isIdentityCreation) {
    apiKey.usage.identitiesCreated++;
  }
  
  // Salva no banco
  await db.setApiKey(apiKey.hashedKey, apiKey);
  
  return {
    allowed: true,
    limits: {
      identitiesRemaining: apiKey.rateLimit.identitiesPerMonth === -1 
        ? -1 
        : apiKey.rateLimit.identitiesPerMonth - apiKey.usage.identitiesCreated,
      requestsPerMinute: reqLimit === -1 
        ? -1 
        : reqLimit - apiKey.usage.requestsThisMinute
    }
  };
}

/**
 * Lista API keys de um usuário (sem expor as keys completas)
 */
export async function listUserApiKeys(userId: string): Promise<ApiKey[]> {
  const allKeys = await db.listApiKeys();
  return allKeys.filter(key => key.userId === userId);
}

/**
 * Revoga (desativa) uma API key
 */
export async function revokeApiKey(hashedKey: string): Promise<boolean> {
  const keyData = await db.getApiKey(hashedKey);
  
  if (!keyData) {
    return false;
  }
  
  keyData.isActive = false;
  await db.setApiKey(hashedKey, keyData);
  
  console.log(`[API_KEY] Revoked: ${keyData.name}`);
  return true;
}