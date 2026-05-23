import { v4 as uuidv4 } from 'uuid';
import { Identity } from '../models/Identity';
import { db } from '../config/database';
import { generateKeyPair, hashValue, generateFakeMetadata } from '../utils/crypto';
import { safeLog, safeError } from '../utils/sanitize';
import paranoiaConfig from '../config/paranoia.json';

interface DeadmanConfig {
  deadmanTimer?: number;
  maxAttempts: number;
  regenerateThreshold: number;
  killThreshold: number;
  ttl: number;
  fakeFingerprintEnabled: boolean;
}

export async function createIdentity(
  paranoiaLevel: 'low' | 'medium' | 'high' | 'deadman' = 'medium'
): Promise<{ identity: Identity; privateKey: string }> {
  try {
    const { publicKey, privateKey } = generateKeyPair();
    const config = paranoiaConfig[paranoiaLevel] as DeadmanConfig;
    const now = Date.now();
    const expiresAt = now + (config.ttl * 1000);

    const identity: Identity = {
      id: uuidv4(),
      publicKey,
      privateKeyHash: hashValue(privateKey),
      createdAt: now,
      expiresAt,
      paranoiaLevel,
      fakeMetadata: generateFakeMetadata(),
      attempts: 0,
      totalAttempts: 0,
      regenerationCount: 0,
      attemptsAfterRegenerate: 0,
      lastAttemptAt: now,
      suspiciousIPs: [],
      isAlive: true,
      lastHeartbeat: paranoiaLevel === 'deadman' ? now : undefined,
      lastCheckIn: paranoiaLevel === 'deadman' ? now : undefined,
      deadmanTimerSeconds: paranoiaLevel === 'deadman' ? config.deadmanTimer : undefined,
    };

    safeLog(`[IDENTITY] Creating:`, {
      id: identity.id,
      paranoiaLevel,
      expiresAt: new Date(expiresAt).toISOString(),
    });

    await db.setIdentity(identity.id, identity);

    safeLog(`[IDENTITY] ✅ Created:`, { id: identity.id });

    return { identity, privateKey };
  } catch (error) {
    safeError('[IDENTITY] ❌ Error creating identity:', error);
    throw new Error('Failed to create identity');
  }
}

export async function regenerateIdentity(
  oldIdentityId: string
): Promise<{ identity: Identity; privateKey: string } | null> {
  try {
    const oldIdentity = await db.getIdentity(oldIdentityId);

    if (!oldIdentity) {
      safeLog(`[IDENTITY] Cannot regenerate: not found`, { id: oldIdentityId });
      return null;
    }

    safeLog(`[IDENTITY] 🔄 Regenerating:`, {
      oldId: oldIdentityId,
      totalAttempts: oldIdentity.totalAttempts,
      regenerationCount: oldIdentity.regenerationCount,
    });

    await killIdentity(oldIdentityId);
    const newIdentityResult = await createIdentity(oldIdentity.paranoiaLevel);
    const newIdentity = newIdentityResult.identity;

    newIdentity.totalAttempts = oldIdentity.totalAttempts || 0;
    newIdentity.regenerationCount = (oldIdentity.regenerationCount || 0) + 1;
    newIdentity.attemptsAfterRegenerate = 0;

    await db.setIdentity(newIdentity.id, newIdentity);

    safeLog(`[IDENTITY] ✅ Regenerated:`, {
      oldId: oldIdentityId,
      newId: newIdentity.id,
      totalAttempts: newIdentity.totalAttempts,
      regenerationCount: newIdentity.regenerationCount,
    });

    return { identity: newIdentity, privateKey: newIdentityResult.privateKey };
  } catch (error) {
    safeError('[IDENTITY] ❌ Error regenerating identity:', error);
    throw new Error('Failed to regenerate identity');
  }
}

export async function killIdentity(identityId: string): Promise<boolean> {
  try {
    const identity = await db.getIdentity(identityId);

    if (!identity) {
      safeLog(`[IDENTITY] Kill skipped: not found`, { id: identityId });
      return false;
    }

    safeLog(`[IDENTITY] 💀 KILLING:`, {
      id: identityId,
      totalAttempts: identity.totalAttempts,
      regenerationCount: identity.regenerationCount,
      attemptsAfterRegenerate: identity.attemptsAfterRegenerate,
    });

    identity.isAlive = false;
    await db.setIdentity(identityId, identity);
    await db.deleteIdentity(identityId);

    safeLog(`[IDENTITY] ☠️ KILLED:`, { id: identityId });
    return true;
  } catch (error) {
    safeError('[IDENTITY] ❌ Error killing identity:', error);
    return false;
  }
}

export async function validateIdentity(
  identityId: string,
  privateKey: string
): Promise<(Identity & { isValidSignature: boolean }) | null> {
  try {
    safeLog(`[IDENTITY] 🔍 Validating:`, { id: identityId });

    const identity = await db.getIdentity(identityId);

    if (!identity) {
      safeLog(`[IDENTITY] ❌ Not found:`, { id: identityId });
      return null;
    }

    safeLog(`[IDENTITY] 📊 State:`, {
      id: identityId,
      isAlive: identity.isAlive,
      attempts: identity.attempts,
      totalAttempts: identity.totalAttempts || 0,
      regenerationCount: identity.regenerationCount || 0,
      attemptsAfterRegenerate: identity.attemptsAfterRegenerate || 0,
    });

    if (!identity.isAlive) {
      safeLog(`[IDENTITY] ❌ Dead:`, { id: identityId });
      return null;
    }

    if (identity.expiresAt < Date.now()) {
      safeLog(`[IDENTITY] ❌ Expired:`, { id: identityId });
      await killIdentity(identityId);
      return null;
    }

    const providedHash = hashValue(privateKey);
    const isValidSignature = providedHash === identity.privateKeyHash;

    safeLog(`[IDENTITY] 🔑 Hash match:`, { id: identityId, isValidSignature });

    if (!isValidSignature) {
      safeLog(`[IDENTITY] ❌ Wrong key:`, { id: identityId });
      return { ...identity, isValidSignature: false };
    }

    safeLog(`[IDENTITY] ✅ Valid key:`, { id: identityId });
    return { ...identity, isValidSignature: true };
  } catch (error) {
    safeError('[IDENTITY] ❌ Error validating identity:', error);
    return null;
  }
}