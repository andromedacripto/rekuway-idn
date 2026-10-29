import { Request, Response } from 'express';
import { Router } from 'express';
import { Redis } from '@upstash/redis';
import { safeLog, safeError, safeWarn } from '../utils/sanitize';
import { getClientIp } from '../utils/clientIp';

interface VerifyIdentityRequest {
  identityId: string;
  context: {
    ip: string;
    userAgent: string;
    device: string;
  };
}

interface StoredIdentity {
  id: string;
  createdAt: number;
  lastVerified?: number;
  suspiciousAttempts: number;
  paranoiaLevel: string;
  destroyed?: boolean;
  isAlive: boolean;
  metadata?: {
    ip?: string;
    userAgent?: string;
    device?: string;
    location?: string;
  };
}

type SecurityAction = 'ALLOW' | 'LIE' | 'KILL';

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
});

const IDENTITY_TTL = 3600;
const MAX_SUSPICIOUS_ATTEMPTS = 3;

const FAKE_IPS = ['203.0.113.0', '198.51.100.42', '192.0.2.123', '203.0.113.255'];
const FAKE_LOCATIONS = [
  'São Paulo, Brazil',
  'Rio de Janeiro, Brazil',
  'Brasília, Brazil',
  'Belo Horizonte, Brazil',
];
const FAKE_DEVICES = ['Desktop', 'Mobile Android', 'iPhone', 'Tablet'];

function generateFakeMetadata() {
  return {
    ip: FAKE_IPS[Math.floor(Math.random() * FAKE_IPS.length)],
    location: FAKE_LOCATIONS[Math.floor(Math.random() * FAKE_LOCATIONS.length)],
    device: FAKE_DEVICES[Math.floor(Math.random() * FAKE_DEVICES.length)],
  };
}

function calculateSecurityAction(
  identity: StoredIdentity,
  contextMismatch: boolean
): SecurityAction {
  const destroyed = identity.destroyed || !identity.isAlive;
  if (destroyed) return 'KILL';
  if ((identity.suspiciousAttempts || 0) >= MAX_SUSPICIOUS_ATTEMPTS) return 'KILL';
  if (contextMismatch && (identity.suspiciousAttempts || 0) >= 1) return 'LIE';
  return 'ALLOW';
}

function detectContextMismatch(
  stored: StoredIdentity,
  current: VerifyIdentityRequest['context']
): boolean {
  if (!stored.metadata?.ip || !stored.metadata?.device) return false;
  const storedIPParts = stored.metadata.ip.split('.');
  const currentIPParts = current.ip.split('.');
  const ipMismatch =
    storedIPParts[0] !== currentIPParts[0] || storedIPParts[1] !== currentIPParts[1];
  const deviceMismatch = stored.metadata.device.toLowerCase() !== current.device.toLowerCase();
  return ipMismatch || deviceMismatch;
}

function validateRequest(body: unknown): {
  valid: boolean;
  error?: string;
  data?: VerifyIdentityRequest;
} {
  if (!body) return { valid: false, error: 'Request body is required' };
  const b = body as Record<string, unknown>;
  const { identityId, context } = b;
  if (!identityId || typeof identityId !== 'string')
    return { valid: false, error: 'identityId is required and must be a string' };
  if (!context || typeof context !== 'object')
    return { valid: false, error: 'context is required and must be an object' };
  const ctx = context as Record<string, unknown>;
  if (!ctx.ip || typeof ctx.ip !== 'string')
    return { valid: false, error: 'context.ip is required' };
  if (!ctx.userAgent || typeof ctx.userAgent !== 'string')
    return { valid: false, error: 'context.userAgent is required' };
  if (!ctx.device || typeof ctx.device !== 'string')
    return { valid: false, error: 'context.device is required' };
  return { valid: true, data: body as VerifyIdentityRequest };
}

export async function verifyIdentity(req: Request, res: Response) {
  const startTime = Date.now();

  try {
    const validation = validateRequest(req.body);

    if (!validation.valid) {
      safeError('[VERIFY] Validation failed:', {
        error: validation.error,
        ip: getClientIp(req),
        timestamp: new Date().toISOString(),
      });
      return res.status(400).json({ success: false, error: validation.error });
    }

    const { identityId, context } = validation.data!;

    safeLog('[VERIFY] Request received:', {
      idPrefix: identityId.substring(0, 8) + '...',
      device: context.device,
      timestamp: new Date().toISOString(),
    });

    const redisKey = `identity:${identityId}`;
    const identityData = await redis.get<StoredIdentity>(redisKey);

    if (!identityData) {
      safeWarn('[VERIFY] Identity not found:', {
        idPrefix: identityId.substring(0, 8) + '...',
        timestamp: new Date().toISOString(),
      });
      return res.status(404).json({ success: false, error: 'Identity not found or expired' });
    }

    if (!identityData.isAlive || identityData.destroyed) {
      safeError('[VERIFY] Identity destroyed:', {
        idPrefix: identityId.substring(0, 8) + '...',
        timestamp: new Date().toISOString(),
      });
      return res
        .status(403)
        .json({ success: false, action: 'KILL', reason: 'Identity permanently destroyed' });
    }

    if (typeof identityData.suspiciousAttempts === 'undefined') identityData.suspiciousAttempts = 0;

    const contextMismatch = detectContextMismatch(identityData, context);

    if (contextMismatch) {
      identityData.suspiciousAttempts += 1;
      safeWarn('[VERIFY] Context mismatch:', {
        idPrefix: identityId.substring(0, 8) + '...',
        suspiciousAttempts: identityData.suspiciousAttempts,
        timestamp: new Date().toISOString(),
      });
    }

    const action = calculateSecurityAction(identityData, contextMismatch);

    switch (action) {
      case 'ALLOW':
        identityData.lastVerified = Date.now();
        await redis.setex(redisKey, IDENTITY_TTL, identityData);
        safeLog('[VERIFY] ✅ ALLOW:', {
          idPrefix: identityId.substring(0, 8) + '...',
          suspiciousAttempts: identityData.suspiciousAttempts,
          durationMs: Date.now() - startTime,
        });
        return res
          .status(200)
          .json({ success: true, action: 'ALLOW', message: 'Identity verified successfully' });

      case 'LIE':
        identityData.suspiciousAttempts += 1;
        await redis.setex(redisKey, IDENTITY_TTL, identityData);
        safeWarn('[VERIFY] 🎭 LIE:', {
          idPrefix: identityId.substring(0, 8) + '...',
          suspiciousAttempts: identityData.suspiciousAttempts,
          durationMs: Date.now() - startTime,
        });
        return res.status(200).json({
          success: false,
          action: 'LIE',
          identity: { id: identityId, metadata: generateFakeMetadata() },
          warning: '⚠️ LAST CHANCE',
        });

      case 'KILL':
        identityData.destroyed = true;
        identityData.isAlive = false;
        await redis.setex(redisKey, 86400, identityData);
        safeError('[VERIFY] 💀 KILL:', {
          idPrefix: identityId.substring(0, 8) + '...',
          suspiciousAttempts: identityData.suspiciousAttempts,
          reason: 'Threshold exceeded',
          durationMs: Date.now() - startTime,
        });
        return res
          .status(403)
          .json({ success: false, action: 'KILL', reason: 'Identity permanently destroyed' });
    }
  } catch (error) {
    safeError('[VERIFY] Critical error:', {
      error: error instanceof Error ? error.message : 'Unknown error',
      durationMs: Date.now() - startTime,
      timestamp: new Date().toISOString(),
    });
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
}

const router = Router();
router.post('/', verifyIdentity);
export default router;
