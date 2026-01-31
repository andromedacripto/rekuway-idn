import { v4 as uuidv4 } from 'uuid';
import { Identity } from '../models/Identity';
import { db } from '../config/database';
import { generateKeyPair, hashValue, generateFakeMetadata } from '../utils/crypto';
import paranoiaConfig from '../config/paranoia.json';

export async function createIdentity(
  paranoiaLevel: 'low' | 'medium' | 'high' | 'deadman' = 'medium'
): Promise<{ identity: Identity; privateKey: string }> {
  try {
    const { publicKey, privateKey } = generateKeyPair();
    const config = paranoiaConfig[paranoiaLevel];
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
      deadmanTimerSeconds: paranoiaLevel === 'deadman' ? (config as any).deadmanTimer : undefined
    };

    console.log(`[IDENTITY] Creating identity: ${identity.id}`);
    console.log(`[IDENTITY]   ├─ Level: ${paranoiaLevel}`);
    console.log(`[IDENTITY]   ├─ Hash: ${identity.privateKeyHash.substring(0, 20)}...`);
    console.log(`[IDENTITY]   └─ Expires: ${new Date(expiresAt).toISOString()}`);
    
    await db.setIdentity(identity.id, identity);
    console.log(`[IDENTITY] ✅ Created: ${identity.id}`);

    return { identity, privateKey };
  } catch (error) {
    console.error('[IDENTITY] ❌ Error creating identity:', error);
    throw new Error('Failed to create identity');
  }
}

export async function regenerateIdentity(oldIdentityId: string): Promise<{ identity: Identity; privateKey: string } | null> {
  try {
    const oldIdentity = await db.getIdentity(oldIdentityId);
    
    if (!oldIdentity) {
      console.log(`[IDENTITY] Cannot regenerate: identity ${oldIdentityId} not found`);
      return null;
    }

    console.log(`[IDENTITY] 🔄 Regenerating: ${oldIdentityId}`);
    console.log(`[IDENTITY]   ├─ Old total attempts: ${oldIdentity.totalAttempts}`);
    console.log(`[IDENTITY]   └─ Old regenerations: ${oldIdentity.regenerationCount}`);

    await killIdentity(oldIdentityId);
    const newIdentityResult = await createIdentity(oldIdentity.paranoiaLevel);
    const newIdentity = newIdentityResult.identity;
    
    newIdentity.totalAttempts = oldIdentity.totalAttempts || 0;
    newIdentity.regenerationCount = (oldIdentity.regenerationCount || 0) + 1;
    newIdentity.attemptsAfterRegenerate = 0;
    
    await db.setIdentity(newIdentity.id, newIdentity);

    console.log(`[IDENTITY] ✅ Regenerated: ${oldIdentityId} -> ${newIdentity.id}`);
    console.log(`[IDENTITY]   ├─ New total attempts: ${newIdentity.totalAttempts}`);
    console.log(`[IDENTITY]   └─ New regenerations: ${newIdentity.regenerationCount}`);

    return { identity: newIdentity, privateKey: newIdentityResult.privateKey };
  } catch (error) {
    console.error('[IDENTITY] ❌ Error regenerating identity:', error);
    throw new Error('Failed to regenerate identity');
  }
}

export async function killIdentity(identityId: string): Promise<boolean> {
  try {
    const identity = await db.getIdentity(identityId);
    
    if (!identity) {
      console.log(`[IDENTITY] Kill failed: identity ${identityId} not found`);
      return false;
    }

    console.log(`[IDENTITY] 💀 KILLING: ${identityId}`);
    console.log(`[IDENTITY]   ├─ Total attempts: ${identity.totalAttempts}`);
    console.log(`[IDENTITY]   ├─ Regenerations: ${identity.regenerationCount}`);
    console.log(`[IDENTITY]   └─ Attempts after regenerate: ${identity.attemptsAfterRegenerate}`);

    identity.isAlive = false;
    await db.setIdentity(identityId, identity);
    await db.deleteIdentity(identityId);

    console.log(`[IDENTITY] ☠️ KILLED: ${identityId}`);
    return true;
  } catch (error) {
    console.error('[IDENTITY] ❌ Error killing identity:', error);
    return false;
  }
}

/**
 * ✅ CORRIGIDO: Retorna identity com isValidSignature flag
 * ✅ NÃO incrementa attempts (isso é feito em identityRoutes.ts)
 */
export async function validateIdentity(
  identityId: string, 
  privateKey: string
): Promise<(Identity & { isValidSignature: boolean }) | null> {
  try {
    console.log(`[IDENTITY] ========================================`);
    console.log(`[IDENTITY] 🔍 Validating: ${identityId}`);
    
    const identity = await db.getIdentity(identityId);

    if (!identity) {
      console.log(`[IDENTITY] ❌ Not found: ${identityId}`);
      return null;
    }

    console.log(`[IDENTITY] 📊 Current state:`);
    console.log(`[IDENTITY]   ├─ isAlive: ${identity.isAlive}`);
    console.log(`[IDENTITY]   ├─ attempts: ${identity.attempts}`);
    console.log(`[IDENTITY]   ├─ totalAttempts: ${identity.totalAttempts || 0}`);
    console.log(`[IDENTITY]   ├─ regenerations: ${identity.regenerationCount || 0}`);
    console.log(`[IDENTITY]   └─ attemptsAfterRegenerate: ${identity.attemptsAfterRegenerate || 0}`);

    if (!identity.isAlive) {
      console.log(`[IDENTITY] ❌ Dead: ${identityId}`);
      return null;
    }

    if (identity.expiresAt < Date.now()) {
      console.log(`[IDENTITY] ❌ Expired: ${identityId}`);
      await killIdentity(identityId);
      return null;
    }

    // ✅ VALIDAÇÃO CRIPTOGRÁFICA
    const providedHash = hashValue(privateKey);
    const storedHash = identity.privateKeyHash;
    const isValidSignature = providedHash === storedHash;
    
    console.log(`[IDENTITY] 🔑 Provided hash: ${providedHash.substring(0, 20)}...`);
    console.log(`[IDENTITY] 🔑 Stored hash:   ${storedHash.substring(0, 20)}...`);
    console.log(`[IDENTITY] 🔑 Hash match: ${isValidSignature}`);

    if (!isValidSignature) {
      console.log(`[IDENTITY] ❌ Wrong key for ${identityId}`);
      console.log(`[IDENTITY] ⚠️ Returning identity with isValidSignature=false`);
      console.log(`[IDENTITY] ⚠️ Routes will handle attempt increment`);
      console.log(`[IDENTITY] ========================================`);
      
      // ✅ RETORNA IDENTITY COM FLAG FALSE (não incrementa attempts aqui!)
      return {
        ...identity,
        isValidSignature: false
      };
    }

    console.log(`[IDENTITY] ✅ Valid key for ${identityId}`);
    console.log(`[IDENTITY] ========================================`);
    
    // ✅ RETORNA IDENTITY COM FLAG TRUE
    return {
      ...identity,
      isValidSignature: true
    };
  } catch (error) {
    console.error('[IDENTITY] ❌ Error validating identity:', error);
    return null;
  }
}