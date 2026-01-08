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

    // Cria a identidade com TODOS os campos
    const identity: Identity = {
      id: uuidv4(),
      publicKey,
      privateKeyHash: hashValue(privateKey), // Armazena APENAS o hash
      createdAt: now,
      expiresAt,
      paranoiaLevel,
      fakeMetadata: generateFakeMetadata(),
      
      // 🔥 Contadores do sistema defensivo híbrido
      attempts: 0,
      totalAttempts: 0,                    // Inicia zerado
      regenerationCount: 0,                // Inicia zerado
      attemptsAfterRegenerate: 0,          // Inicia zerado
      
      lastAttemptAt: now,
      suspiciousIPs: [],
      isAlive: true,
      
      // Deadman switch (só para nível deadman)
      lastHeartbeat: paranoiaLevel === 'deadman' ? now : undefined,
      lastCheckIn: paranoiaLevel === 'deadman' ? now : undefined,
      deadmanTimerSeconds: paranoiaLevel === 'deadman' ? config.deadmanTimer : undefined
    };

    // Salva no banco
    console.log(`[IDENTITY] Creating identity: ${identity.id}`);
    console.log(`[IDENTITY]   ├─ Level: ${paranoiaLevel}`);
    console.log(`[IDENTITY]   ├─ Hash: ${identity.privateKeyHash.substring(0, 20)}...`);
    console.log(`[IDENTITY]   └─ Expires: ${new Date(expiresAt).toISOString()}`);
    
    await db.setIdentity(identity.id, identity);

    console.log(`[IDENTITY] ✅ Created: ${identity.id}`);

    // Retorna identidade + chave privada (usuário deve guardar a chave!)
    return { identity, privateKey };

  } catch (error) {
    console.error('[IDENTITY] ❌ Error creating identity:', error);
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

    console.log(`[IDENTITY] 🔄 Regenerating: ${oldIdentityId}`);
    console.log(`[IDENTITY]   ├─ Old total attempts: ${oldIdentity.totalAttempts}`);
    console.log(`[IDENTITY]   └─ Old regenerations: ${oldIdentity.regenerationCount}`);

    // Mata a identidade antiga
    await killIdentity(oldIdentityId);

    // Cria nova identidade com o mesmo nível de paranoia
    const newIdentityResult = await createIdentity(oldIdentity.paranoiaLevel);
    
    // 🔥 IMPORTANTE: Transfere contadores para nova identidade
    const newIdentity = newIdentityResult.identity;
    newIdentity.totalAttempts = oldIdentity.totalAttempts || 0;
    newIdentity.regenerationCount = (oldIdentity.regenerationCount || 0) + 1;
    newIdentity.attemptsAfterRegenerate = 0; // Reseta contador pós-regeneração
    
    // Salva identidade com contadores transferidos
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

    console.log(`[IDENTITY] 💀 KILLING: ${identityId}`);
    console.log(`[IDENTITY]   ├─ Total attempts: ${identity.totalAttempts}`);
    console.log(`[IDENTITY]   ├─ Regenerations: ${identity.regenerationCount}`);
    console.log(`[IDENTITY]   └─ Attempts after regenerate: ${identity.attemptsAfterRegenerate}`);

    // Marca como morta
    identity.isAlive = false;
    await db.setIdentity(identityId, identity);

    // Deleta do banco
    await db.deleteIdentity(identityId);

    console.log(`[IDENTITY] ☠️ KILLED: ${identityId}`);

    return true;

  } catch (error) {
    console.error('[IDENTITY] ❌ Error killing identity:', error);
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

    // Verifica se ainda está viva
    if (!identity.isAlive) {
      console.log(`[IDENTITY] ❌ Dead: ${identityId}`);
      return null;
    }

    // Verifica se expirou
    if (identity.expiresAt < Date.now()) {
      console.log(`[IDENTITY] ❌ Expired: ${identityId}`);
      await killIdentity(identityId);
      return null;
    }

    // Valida chave privada
    const providedHash = hashValue(privateKey);
    const storedHash = identity.privateKeyHash;
    
    const hashMatch = providedHash === storedHash;
    console.log(`[IDENTITY] 🔑 Hash match: ${hashMatch}`);
    
    if (!hashMatch) {
      console.log(`[IDENTITY] ❌ Wrong key for ${identityId}`);

      // Incrementa contador de tentativas
      identity.attempts++;
      identity.lastAttemptAt = Date.now();
      await db.setIdentity(identityId, identity);

      console.log(`[IDENTITY] 📈 Attempts incremented to: ${identity.attempts}`);
      return null;
    }

    // ✅ SUCESSO - atualiza last attempt mas NÃO incrementa attempts
    identity.lastAttemptAt = Date.now();
    await db.setIdentity(identityId, identity);

    console.log(`[IDENTITY] ✅ Valid key for ${identityId}`);
    console.log(`[IDENTITY] ========================================`);
    
    return identity;

  } catch (error) {
    console.error('[IDENTITY] ❌ Error validating identity:', error);
    return null;
  }
}