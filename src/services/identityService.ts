import { v4 as uuidv4 } from 'uuid';
import { Identity } from '../models/Identity';
import { db } from '../config/database';
import { generateKeyPair, hashValue, generateFakeMetadata } from '../utils/crypto';
import { safeLog, safeError } from '../utils/sanitize';
import { safeEqualString } from '../utils/internalSecret';
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
    const config = paranoiaConfig[paranoiaLevel] as unknown as DeadmanConfig;
    const now = Date.now();
    const expiresAt = now + config.ttl * 1000;

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

    // A identidade nova continua sendo da mesma empresa e da mesma pessoa.
    newIdentity.userId = oldIdentity.userId;
    newIdentity.externalRef = oldIdentity.externalRef;
    newIdentity.totalAttempts = oldIdentity.totalAttempts || 0;
    newIdentity.regenerationCount = (oldIdentity.regenerationCount || 0) + 1;
    newIdentity.attemptsAfterRegenerate = 0;

    await db.setIdentity(newIdentity.id, newIdentity);
    await indexPerson(newIdentity);

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
    const isValidSignature = safeEqualString(providedHash, identity.privateKeyHash);

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

// ─────────────────────────────────────────────
//  Pessoa (externalRef): índice e revogação
// ─────────────────────────────────────────────

const personKey = (userId: string, ref: string, identityId: string) =>
  `person:${userId}:${ref}:${identityId}`;

/** Registra a identidade no índice da pessoa. Sem userId ou externalRef, não faz nada. */
export async function indexPerson(identity: Identity): Promise<void> {
  if (!identity.userId || !identity.externalRef) return;
  const ttl = Math.max(60, Math.ceil((identity.expiresAt - Date.now()) / 1000) + 60);
  await db.set(personKey(identity.userId, identity.externalRef, identity.id), '1', ttl);
}

/**
 * Destrói TODAS as identidades vivas de uma pessoa de uma empresa.
 * Só mexe em identidades cujo userId seja o da empresa que pediu.
 */
export async function revokePerson(
  userId: string,
  externalRef: string
): Promise<{ revoked: number }> {
  const keys = await db.keys(`person:${userId}:${externalRef}:*`);
  let revoked = 0;
  for (const key of keys) {
    const identityId = key.slice(key.lastIndexOf(':') + 1);
    const identity = await db.getIdentity(identityId);
    if (identity && identity.userId === userId && identity.externalRef === externalRef) {
      if (await killIdentity(identityId)) revoked++;
    }
    await db.delete(key);
  }
  safeLog(`[IDENTITY] 🚫 Person revoked:`, { userId, externalRef, revoked });
  return { revoked };
}
