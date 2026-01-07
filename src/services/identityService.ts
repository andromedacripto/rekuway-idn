import { v4 as uuidv4 } from 'uuid';
import { Identity } from '../models/Identity';
import { db } from '../config/database';
import { generateKeyPair, hashValue, generateFakeMetadata } from '../utils/crypto';
import paranoiaConfig from '../config/paranoia.json';

/**
 * Cria uma nova identidade temporária
 * 
 * @param paranoiaLevel - Nível de segurança (low, medium, high, deadman)
 * @returns Identidade criada com chave privada (ÚNICO momento em que a chave privada é exposta)
 */
export async function createIdentity(
  paranoiaLevel: 'low' | 'medium' | 'high' | 'deadman' = 'medium'
): Promise<{ identity: Identity; privateKey: string }> {
  try {
    // Gera par de chaves
    const { publicKey, privateKey } = generateKeyPair();
    
    // Pega configurações do nível de paranoia escolhido
    const config = paranoiaConfig[paranoiaLevel];
    
    const now = Date.now();
    const expiresAt = now + (config.ttlSeconds * 1000);

    // Cria a identidade
    const identity: Identity = {
      id: uuidv4(),
      publicKey,
      privateKeyHash: hashValue(privateKey), // Armazena APENAS o hash
      createdAt: now,
      expiresAt,
      paranoiaLevel,
      fakeMetadata: generateFakeMetadata(),
      attempts: 0,
      lastAttemptAt: now,
      suspiciousIPs: [],
      lastHeartbeat: paranoiaLevel === 'deadman' ? now : undefined,
      isAlive: true
    };

    // Salva no banco
    console.log(`[DEBUG] Saving identity with hash: ${identity.privateKeyHash.substring(0, 20)}...`);
    await db.setIdentity(identity.id, identity);

    console.log(`[IDENTITY] Created new identity: ${identity.id} (level: ${paranoiaLevel})`);

    // Retorna identidade + chave privada (usuário deve guardar a chave!)
    return { identity, privateKey };

  } catch (error) {
    console.error('[IDENTITY] Error creating identity:', error);
    throw new Error('Failed to create identity');
  }
}

/**
 * Regenera uma identidade (cria nova e invalida a antiga)
 * 
 * @param oldIdentityId - ID da identidade antiga
 * @returns Nova identidade com nova chave privada
 */
export async function regenerateIdentity(oldIdentityId: string): Promise<{ identity: Identity; privateKey: string } | null> {
  try {
    // Busca identidade antiga
    const oldIdentity = await db.getIdentity(oldIdentityId);
    
    if (!oldIdentity) {
      console.log(`[IDENTITY] Cannot regenerate: identity ${oldIdentityId} not found`);
      return null;
    }

    // Mata a identidade antiga
    await killIdentity(oldIdentityId);

    // Cria nova identidade com o mesmo nível de paranoia
    const newIdentity = await createIdentity(oldIdentity.paranoiaLevel);

    console.log(`[IDENTITY] Regenerated: ${oldIdentityId} -> ${newIdentity.identity.id}`);

    return newIdentity;

  } catch (error) {
    console.error('[IDENTITY] Error regenerating identity:', error);
    throw new Error('Failed to regenerate identity');
  }
}

/**
 * Destrói uma identidade permanentemente
 * 
 * @param identityId - ID da identidade a ser destruída
 * @returns true se destruída com sucesso
 */
export async function killIdentity(identityId: string): Promise<boolean> {
  try {
    const identity = await db.getIdentity(identityId);
    
    if (!identity) {
      console.log(`[IDENTITY] Kill failed: identity ${identityId} not found`);
      return false;
    }

    // Marca como morta
    identity.isAlive = false;
    await db.setIdentity(identityId, identity);

    // Deleta do banco
    await db.deleteIdentity(identityId);

    console.log(`[IDENTITY] 💀 KILLED: ${identityId}`);

    return true;

  } catch (error) {
    console.error('[IDENTITY] Error killing identity:', error);
    return false;
  }
}

/**
 * Valida uma identidade e atualiza contador de tentativas
 * 
 * @param identityId - ID da identidade
 * @param privateKey - Chave privada fornecida pelo usuário
 * @returns Identidade se válida, null se inválida
 */
export async function validateIdentity(identityId: string, privateKey: string): Promise<Identity | null> {
  try {
    console.log(`[DEBUG] ========================================`);
    console.log(`[DEBUG] Validating identity: ${identityId}`);
    console.log(`[DEBUG] Private key length: ${privateKey.length}`);
    
    const identity = await db.getIdentity(identityId);
    console.log(`[DEBUG] Identity retrieved:`, identity ? 'YES' : 'NO');

    if (!identity) {
      console.log(`[IDENTITY] Validation failed: identity ${identityId} not found`);
      return null;
    }

    console.log(`[DEBUG] Identity isAlive: ${identity.isAlive}`);
    console.log(`[DEBUG] Identity expiresAt: ${identity.expiresAt}`);
    console.log(`[DEBUG] Current time: ${Date.now()}`);

    // Verifica se ainda está viva
    if (!identity.isAlive) {
      console.log(`[IDENTITY] Validation failed: identity ${identityId} is dead`);
      return null;
    }

    // Verifica se expirou
    if (identity.expiresAt < Date.now()) {
      console.log(`[IDENTITY] Validation failed: identity ${identityId} expired`);
      await killIdentity(identityId);
      return null;
    }

    // Valida chave privada
    const providedHash = hashValue(privateKey);
    const storedHash = identity.privateKeyHash;
    
    console.log(`[DEBUG] Provided hash: ${providedHash}`);
    console.log(`[DEBUG] Stored hash:   ${storedHash}`);
    console.log(`[DEBUG] Hashes match: ${providedHash === storedHash}`);
    
    if (providedHash !== storedHash) {
      console.log(`[IDENTITY] Validation failed: wrong private key for ${identityId}`);

      // Incrementa contador de tentativas
      identity.attempts++;
      identity.lastAttemptAt = Date.now();
      await db.setIdentity(identityId, identity);

      return null;
    }

    // ✅ SUCESSO - atualiza last attempt
    identity.lastAttemptAt = Date.now();
    await db.setIdentity(identityId, identity);

    console.log(`[IDENTITY] ✅ Validation successful for ${identityId}`);
    return identity;

  } catch (error) {
    console.error('[IDENTITY] Error validating identity:', error);
    return null;
  }
}

    console.log(`[IDENTITY] Validated: ${identityId}`);
    return identity;

  } catch (error) {
    console.error('[IDENTITY] Error validating identity:', error);
    return null;
  }
}