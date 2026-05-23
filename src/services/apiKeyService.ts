import crypto from 'crypto';
import { db } from '../config/database';
import { safeLog, safeError } from '../utils/sanitize';

export interface ApiKey {
  key: string;
  hashedKey: string;
  name: string;
  userId: string;
  tier: 'hobby' | 'startup' | 'business' | 'enterprise';
  rateLimit: {
    identitiesPerMonth: number;
    requestsPerMinute: number;
  };
  usage: {
    identitiesCreated: number;
    requestsThisMinute: number;
    lastRequest: number;
    resetDate: number;
    totalRequests?: number;
    blockedRequests?: number;
  };
  createdAt: number;
  isActive: boolean;
}

const TIERS = {
  hobby:      { identitiesPerMonth: 100,   requestsPerMinute: 10    },
  startup:    { identitiesPerMonth: 1000,  requestsPerMinute: 100   },
  business:   { identitiesPerMonth: 10000, requestsPerMinute: 1000  },
  enterprise: { identitiesPerMonth: -1,    requestsPerMinute: -1    },
};

export function generateApiKey(): string {
  const randomPart = crypto.randomBytes(16).toString('hex');
  return `rkwy_live_${randomPart}`;
}

function hashApiKey(apiKey: string): string {
  return crypto.createHash('sha256').update(apiKey).digest('hex');
}

export async function createApiKey(
  userId: string,
  name: string,
  tier: ApiKey['tier'] = 'hobby'
): Promise<{ apiKey: ApiKey; plainKey: string }> {
  const plainKey  = generateApiKey();
  const hashedKey = hashApiKey(plainKey);

  const now       = Date.now();
  const resetDate = now + (30 * 24 * 60 * 60 * 1000);

  const apiKey: ApiKey = {
    key: plainKey.substring(0, 20) + '...', // Parcial — apenas para exibição
    hashedKey,
    name,
    userId,
    tier,
    rateLimit: TIERS[tier],
    usage: {
      identitiesCreated:  0,
      requestsThisMinute: 0,
      lastRequest:        now,
      resetDate,
    },
    createdAt: now,
    isActive:  true,
  };

  await db.setApiKey(hashedKey, apiKey as unknown as Record<string, unknown>);

  // ✅ SEGURO: loga userId e tier, NUNCA a plainKey ou hashedKey completo
  safeLog(`[API_KEY] Created:`, { userId, tier, name });

  return { apiKey, plainKey }; // plainKey retornada UMA VEZ para a rota
}

export async function validateApiKey(apiKey: string): Promise<ApiKey | null> {
  if (!apiKey || !apiKey.startsWith('rkwy_live_')) return null;

  const hashedKey = hashApiKey(apiKey);
  const keyData = await db.getApiKey(hashedKey) as unknown as ApiKey | null;
  if (!keyData || !keyData.isActive) return null;
  return keyData;
}

export async function checkRateLimit(
  apiKey: ApiKey,
  isIdentityCreation = false
): Promise<{
  allowed: boolean;
  reason?: string;
  limits: { identitiesRemaining: number; requestsPerMinute: number };
}> {
  const now = Date.now();

  if (now > apiKey.usage.resetDate) {
    apiKey.usage.identitiesCreated = 0;
    apiKey.usage.resetDate = now + (30 * 24 * 60 * 60 * 1000);
  }

  if (now - apiKey.usage.lastRequest > 60000) {
    apiKey.usage.requestsThisMinute = 0;
  }

  if (isIdentityCreation) {
    const limit = apiKey.rateLimit.identitiesPerMonth;
    if (limit !== -1 && apiKey.usage.identitiesCreated >= limit) {
      return {
        allowed: false,
        reason: `Monthly limit of ${limit} identities exceeded.`,
        limits: { identitiesRemaining: 0, requestsPerMinute: apiKey.rateLimit.requestsPerMinute },
      };
    }
  }

  const reqLimit = apiKey.rateLimit.requestsPerMinute;
  if (reqLimit !== -1 && apiKey.usage.requestsThisMinute >= reqLimit) {
    return {
      allowed: false,
      reason: `Rate limit of ${reqLimit} req/min exceeded.`,
      limits: {
        identitiesRemaining: apiKey.rateLimit.identitiesPerMonth - apiKey.usage.identitiesCreated,
        requestsPerMinute: 0,
      },
    };
  }

  apiKey.usage.requestsThisMinute++;
  apiKey.usage.totalRequests = (apiKey.usage.totalRequests || 0) + 1;
  apiKey.usage.lastRequest   = now;

  if (isIdentityCreation) apiKey.usage.identitiesCreated++;

  await db.setApiKey(apiKey.hashedKey, apiKey as unknown as Record<string, unknown>);

  return {
    allowed: true,
    limits: {
      identitiesRemaining: apiKey.rateLimit.identitiesPerMonth === -1
        ? -1
        : apiKey.rateLimit.identitiesPerMonth - apiKey.usage.identitiesCreated,
      requestsPerMinute: reqLimit === -1 ? -1 : reqLimit - apiKey.usage.requestsThisMinute,
    },
  };
}
export async function listUserApiKeys(userId: string): Promise<ApiKey[]> {

  const allKeys = await db.listApiKeys() as unknown as ApiKey[];
  return allKeys.filter(key => key.userId === userId);
}

export async function revokeApiKey(hashedKey: string): Promise<boolean> {
  const keyData = await db.getApiKey(hashedKey);
  if (!keyData) return false;

  keyData.isActive = false;
  await db.setApiKey(hashedKey, keyData);

  // ✅ SEGURO: loga apenas o name, nunca a key
  safeLog(`[API_KEY] Revoked:`, { name: keyData.name });
  return true;
}

export async function incrementBlockedRequests(apiKeyString: string): Promise<void> {
  try {
    const hashedKey = crypto.createHash('sha256').update(apiKeyString).digest('hex');
    let keyData = await db.getApiKey(hashedKey) as unknown as ApiKey | null;

    if (!keyData) {
      keyData = {
        key:      'invalid',
        hashedKey,
        name:     'Invalid/Blocked Key',
        userId:   'unknown',
        tier:     'hobby',
        rateLimit: { identitiesPerMonth: 0, requestsPerMinute: 0 },
        usage: {
          identitiesCreated:  0,
          requestsThisMinute: 0,
          lastRequest:        Date.now(),
          resetDate:          Date.now() + (30 * 24 * 60 * 60 * 1000),
          totalRequests:      0,
          blockedRequests:    0,
        },
        createdAt: Date.now(),
        isActive:  false,
      };
    }

    keyData.usage.blockedRequests = (keyData.usage.blockedRequests || 0) + 1;
    keyData.usage.totalRequests   = (keyData.usage.totalRequests   || 0) + 1;
    await db.setApiKey(hashedKey, keyData as unknown as Record<string, unknown>);
  } catch (error) {
    safeError('[API_KEY] Error incrementing blocked:', error);
  }
}
