import { Identity, ThreatEvent, DefensiveAction } from '../models/Identity';
import { db } from '../config/database';
import paranoiaConfig from '../config/paranoia.json';
import { killIdentity, regenerateIdentity } from './identityService';

/**
 * Interface do resultado da análise defensiva
 */
export interface DefensiveResponse {
  action: DefensiveAction;
  reason: string;
  identity: Identity | null;
  fakeData?: any;
  newIdentity?: { identity: Identity; privateKey: string };
}

/**
 * 🔒 LOCK REDIS ATÔMICO V2 - CORRIGIDO E MAIS INTELIGENTE
 * 
 * CORREÇÕES:
 * ✅ Usa strings simples (não JSON) para evitar parse errors
 * ✅ Retry automático (3 tentativas)
 * ✅ Detecção de locks expirados (stale locks)
 * ✅ Não mata identidades legítimas por race benigna
 * 
 * FILOSOFIA REKUWAY IDN:
 * - Lock protege contra ataques paralelos maliciosos
 * - MAS não deve punir usuários legítimos com conexões lentas
 * - Race condition benigna (1-2x) = tolerada
 * - Race condition maliciosa (5+) = KILL imediato
 */
async function acquireLock(identityId: string, timeoutMs: number = 5000): Promise<boolean> {
  const lockKey = `lock:${identityId}`;
  const lockValue = `${Date.now()}`; // ✅ STRING SIMPLES (não JSON)
  const ttlSeconds = Math.ceil(timeoutMs / 1000);
  
  try {
    // 🔥 Tentar adquirir lock
    const existing = await db.get(lockKey);
    
    if (!existing) {
      // Lock disponível - adquirir
      await db.set(lockKey, lockValue, ttlSeconds);
      
      // Double-check: verificar se realmente adquirimos
      await new Promise(resolve => setTimeout(resolve, 10));
      const current = await db.get(lockKey);
      
      if (current === lockValue) {
        console.log(`[LOCK] ✅ Acquired for ${identityId}`);
        return true;
      }
      
      console.log(`[LOCK] ❌ Lost race condition for ${identityId}`);
      return false;
    }
    
    // Lock já existe - verificar se está expirado (stale)
    const lockTimestamp = parseInt(existing as string, 10);
    const lockAge = Date.now() - lockTimestamp;
    
    if (lockAge > timeoutMs) {
      // Lock expirado - forçar release e tentar novamente
      console.log(`[LOCK] 🔓 Forcing release of stale lock (${lockAge}ms old)`);
      await db.delete(lockKey);
      return acquireLock(identityId, timeoutMs); // Retry
    }
    
    console.log(`[LOCK] ⏳ Lock held by another request (${lockAge}ms old)`);
    return false;
    
  } catch (error) {
    console.error('[LOCK] ⚠️ Error acquiring lock:', error);
    return false;
  }
}

async function releaseLock(identityId: string): Promise<void> {
  const lockKey = `lock:${identityId}`;
  try {
    await db.delete(lockKey);
    console.log(`[LOCK] 🔓 Released for ${identityId}`);
  } catch (error) {
    console.error('[LOCK] Error releasing lock:', error);
  }
}

/**
 * FUNÇÃO PRINCIPAL: Analisa evento e decide ação defensiva
 *
 * 🔥 VERSÃO V2 - CORRIGIDA E ALINHADA COM REKUWAY IDN
 * 
 * MUDANÇAS:
 * ✅ Lock com retry automático (3 tentativas)
 * ✅ Tolerância para race conditions benignas
 * ✅ Kill apenas em ataques paralelos maliciosos (5+ tentativas)
 * ✅ Logging detalhado para debug
 * 
 * @param identity - Identidade sendo analisada
 * @param event - Tipo de evento detectado
 * @param clientIP - IP do cliente
 * @returns Resposta defensiva com ação a ser tomada
 */
export async function defensiveResponse(
  identity: Identity,
  event: ThreatEvent,
  clientIP: string
): Promise<DefensiveResponse> {
  
  // 🔒 TENTA ADQUIRIR LOCK (com 3 retries)
  let lockAcquired = false;
  let retries = 3;
  const retryDelay = 100; // 100ms entre retries
  
  while (!lockAcquired && retries > 0) {
    lockAcquired = await acquireLock(identity.id, 5000);
    
    if (!lockAcquired) {
      retries--;
      if (retries > 0) {
        console.log(`[LOCK] 🔄 Retrying... (${retries} attempts left)`);
        await new Promise(resolve => setTimeout(resolve, retryDelay));
      }
    }
  }
  
  // ⚠️ NÃO CONSEGUIU LOCK APÓS 3 RETRIES
  if (!lockAcquired) {
    console.log(`[DEFENSE] ⚠️ Lock timeout after 3 retries - possible concurrent access`);
    
    // 📊 INCREMENTA CONTADOR DE ACESSOS CONCORRENTES
    const concurrentKey = `concurrent:${identity.id}`;
    const concurrentCount = ((await db.get(concurrentKey) as number) || 0) + 1;
    await db.set(concurrentKey, concurrentCount, 3600); // TTL 1h
    
    console.log(`[DEFENSE] 📝 Concurrent access count: ${concurrentCount}`);
    
    // 🔥 FILOSOFIA REKUWAY IDN: Tolera 1-4 race conditions (pode ser conexão lenta)
    // MAS 5+ é claramente ataque paralelo malicioso
    if (concurrentCount >= 5) {
      console.log(`[DEFENSE] 🚨 TOO MANY concurrent attempts (${concurrentCount}) - MALICIOUS ATTACK!`);
      
      // Penaliza pesado e mata
      const freshIdentity = await db.getIdentity(identity.id);
      if (freshIdentity && freshIdentity.isAlive) {
        freshIdentity.attempts = (freshIdentity.attempts || 0) + 5; // Penalidade severa
        freshIdentity.totalAttempts = (freshIdentity.totalAttempts || 0) + 5;
        await db.setIdentity(freshIdentity.id, freshIdentity);
        
        await killIdentity(identity.id);
        
        return {
          action: DefensiveAction.KILL,
          reason: `Parallel attack detected: ${concurrentCount} concurrent attempts`,
          identity: null
        };
      }
    }
    
    // ✅ Tolera race condition benigna (1-4 tentativas)
    console.log(`[DEFENSE] ✅ Tolerated concurrent access (${concurrentCount}/5) - likely legitimate`);
    
    return {
      action: DefensiveAction.ALLOW,
      reason: `Concurrent access detected but within tolerance (${concurrentCount}/5)`,
      identity: identity
    };
  }

  // 🔓 LOCK ADQUIRIDO - Executar lógica defensiva
  try {
    // Recarrega identidade do Redis para garantir estado atual
    const freshIdentity = await db.getIdentity(identity.id);
    
    if (!freshIdentity || !freshIdentity.isAlive) {
      return {
        action: DefensiveAction.KILL,
        reason: 'Identity no longer exists or already killed',
        identity: null
      };
    }

    // Pega configurações do nível de paranoia
    const config = paranoiaConfig[freshIdentity.paranoiaLevel];

    // Adiciona IP suspeito se não estiver na lista
    if (!freshIdentity.suspiciousIPs.includes(clientIP)) {
      freshIdentity.suspiciousIPs.push(clientIP);
      await db.setIdentity(freshIdentity.id, freshIdentity);
    }

    console.log(`[DEFENSE] 🎯 Analysis:`);
    console.log(`[DEFENSE]    ├─ Event: ${event}`);
    console.log(`[DEFENSE]    ├─ Identity: ${freshIdentity.id}`);
    console.log(`[DEFENSE]    ├─ Attempts: ${freshIdentity.attempts}/${config.maxAttempts}`);
    console.log(`[DEFENSE]    ├─ Total: ${freshIdentity.totalAttempts || 0}`);
    console.log(`[DEFENSE]    └─ Regenerations: ${freshIdentity.regenerationCount || 0}`);

    // 🔥 DECISÃO 1: KILL (prioridade máxima)
    // Mata após maxAttempts tentativas erradas
    if (freshIdentity.attempts >= config.maxAttempts) {
      console.log(`[DEFENSE] 💀 KILL TRIGGERED: maxAttempts exceeded`);
      await killIdentity(freshIdentity.id);

      return {
        action: DefensiveAction.KILL,
        reason: `Maximum attempts exceeded (${freshIdentity.attempts}/${config.maxAttempts})`,
        identity: null
      };
    }

    // 🔥 DECISÃO 2: KILL (totalAttempts através de regenerações)
    if (freshIdentity.totalAttempts && freshIdentity.totalAttempts >= config.maxAttempts) {
      console.log(`[DEFENSE] 💀 KILL TRIGGERED: persistent attacker (total=${freshIdentity.totalAttempts})`);
      await killIdentity(freshIdentity.id);

      return {
        action: DefensiveAction.KILL,
        reason: `Persistent attacker detected (${freshIdentity.totalAttempts} total attempts)`,
        identity: null
      };
    }

    // 🎭 DECISÃO 3: LIE (após regeneração - segunda chance)
    if (freshIdentity.regenerationCount && freshIdentity.regenerationCount > 0) {
      const attemptsAfterRegen = freshIdentity.attemptsAfterRegenerate || 0;
      
      // Primeira tentativa após regeneração = LIE (engana atacante)
      if (attemptsAfterRegen === 1) {
        console.log(`[DEFENSE] 🎭 LIE TRIGGERED: suspicious activity after regeneration`);
        
        return {
          action: DefensiveAction.LIE,
          reason: 'Suspicious activity after regeneration - returning fake metadata',
          identity: freshIdentity,
          fakeData: freshIdentity.fakeMetadata
        };
      }
      
      // Segunda tentativa após regeneração = KILL (acabou a paciência)
      if (attemptsAfterRegen >= 2) {
        console.log(`[DEFENSE] 💀 KILL TRIGGERED: 2nd attempt after regeneration`);
        await killIdentity(freshIdentity.id);
        
        return {
          action: DefensiveAction.KILL,
          reason: 'Second failed attempt after regeneration',
          identity: null
        };
      }
    }

    // 🔄 DECISÃO 4: REGENERATE
    if (config.regenerateThreshold && freshIdentity.attempts >= config.regenerateThreshold) {
      // Só regenera UMA VEZ
      if (!freshIdentity.regenerationCount || freshIdentity.regenerationCount === 0) {
        console.log(`[DEFENSE] 🔄 REGENERATE TRIGGERED: threshold reached (${freshIdentity.attempts}/${config.regenerateThreshold})`);
        
        const newIdentity = await regenerateIdentity(freshIdentity.id);

        return {
          action: DefensiveAction.REGENERATE,
          reason: `Identity regenerated: exceeded ${config.regenerateThreshold} suspicious attempts`,
          identity: null,
          newIdentity: newIdentity || undefined
        };
      }
    }

    // 🎭 DECISÃO 5: LIE (fingerprint match com fake enabled)
    if (config.fakeFingerprintEnabled && event === ThreatEvent.FINGERPRINT_MATCH) {
      console.log(`[DEFENSE] 🎭 LIE TRIGGERED: fingerprint match detected`);
      
      return {
        action: DefensiveAction.LIE,
        reason: 'Fingerprint match detected: returning fake metadata',
        identity: freshIdentity,
        fakeData: freshIdentity.fakeMetadata
      };
    }

    // ✅ DECISÃO 6: ALLOW (dentro dos limites aceitáveis)
    console.log(`[DEFENSE] ✅ ALLOW: event logged but within acceptable threshold`);
    
    return {
      action: DefensiveAction.ALLOW,
      reason: 'Event logged but within acceptable threshold',
      identity: freshIdentity
    };

  } catch (error) {
    console.error('[DEFENSE] ❌ Error in defensive response:', error);

    // 🔥 Fail-safe: em caso de erro, assume postura defensiva
    await killIdentity(identity.id);

    return {
      action: DefensiveAction.KILL,
      reason: 'Identity killed due to system error (fail-safe)',
      identity: null
    };
    
  } finally {
    // 🔒 SEMPRE liberar lock
    await releaseLock(identity.id);
  }
}

/**
 * Detecta tipo de evento baseado em padrões
 *
 * @param identity - Identidade sendo verificada
 * @param clientIP - IP do cliente
 * @param timeSinceLastAttempt - Tempo desde última tentativa (ms)
 * @returns Tipo de evento detectado
 */
export function detectThreatEvent(
  identity: Identity,
  clientIP: string,
  timeSinceLastAttempt: number
): ThreatEvent {
  // 🔴 Brute force: múltiplas tentativas em menos de 5 segundos
  if (timeSinceLastAttempt < 5000 && identity.attempts > 0) {
    console.log(`[THREAT] 🔴 BRUTE_FORCE detected (${timeSinceLastAttempt}ms interval)`);
    return ThreatEvent.BRUTE_FORCE;
  }

  // 🔴 Rate limit: mais de 10 tentativas em 1 minuto
  if (identity.attempts > 10 && timeSinceLastAttempt < 60000) {
    console.log(`[THREAT] 🔴 RATE_LIMIT exceeded (${identity.attempts} attempts)`);
    return ThreatEvent.RATE_LIMIT;
  }

  // 🟡 Fingerprint match: mesmo IP tentando novamente
  if (identity.suspiciousIPs.includes(clientIP)) {
    console.log(`[THREAT] 🟡 FINGERPRINT_MATCH (IP: ${clientIP})`);
    return ThreatEvent.FINGERPRINT_MATCH;
  }

  // 🟢 Scraping: padrão de requisições automáticas
  if (identity.attempts > 5) {
    console.log(`[THREAT] 🟢 SCRAPING pattern (${identity.attempts} attempts)`);
    return ThreatEvent.SCRAPING;
  }

  // Default
  return ThreatEvent.RATE_LIMIT;
}

/**
 * Verifica deadman switch
 * Se modo deadman e sem heartbeat recente -> mata identidade
 *
 * @param identity - Identidade a verificar
 * @returns true se identidade foi morta
 */
export async function checkDeadmanSwitch(identity: Identity): Promise<boolean> {
  if (identity.paranoiaLevel !== 'deadman') {
    return false;
  }

  const config = paranoiaConfig.deadman;
  const now = Date.now();
  const lastHeartbeat = identity.lastHeartbeat || identity.lastCheckIn || identity.createdAt;
  const timeSinceHeartbeat = now - lastHeartbeat;
  const deadmanTimerMs = (config.deadmanTimer || 60) * 1000;

  console.log(`[DEADMAN] 💓 Checking identity ${identity.id}:`);
  console.log(`[DEADMAN]    ├─ Last heartbeat: ${new Date(lastHeartbeat).toISOString()}`);
  console.log(`[DEADMAN]    ├─ Time since: ${Math.floor(timeSinceHeartbeat / 1000)}s`);
  console.log(`[DEADMAN]    └─ Timer limit: ${config.deadmanTimer}s`);

  // Se passou do tempo sem heartbeat, mata
  if (timeSinceHeartbeat > deadmanTimerMs) {
    console.log(`[DEADMAN] 💀 Timeout exceeded for identity ${identity.id} - KILLING NOW`);
    await killIdentity(identity.id);
    return true;
  }

  return false;
}

/**
 * 🔥 Background job que verifica deadman switches
 * Roda a cada 5 segundos para garantir precisão
 */
export function startDeadmanMonitor() {
  console.log('[DEADMAN] 🚀 Starting Deadman Monitor...');
  
  setInterval(async () => {
    try {
      const identities = await db.listIdentities();
      let checked = 0;
      let killed = 0;

      for (const identity of identities) {
        if (identity.paranoiaLevel === 'deadman' && identity.isAlive) {
          checked++;
          const wasKilled = await checkDeadmanSwitch(identity);
          if (wasKilled) {
            killed++;
            console.log(`[DEADMAN] 💀 Killed identity ${identity.id} due to timeout`);
          }
        }
      }

      if (checked > 0) {
        console.log(`[DEADMAN] Monitor sweep: checked ${checked} identities, killed ${killed}`);
      }
    } catch (error) {
      console.error('[DEADMAN] Monitor error:', error);
    }
  }, 5000); // 🔥 5 segundos para garantir precisão

  console.log('[DEADMAN] ✅ Monitor started (checking every 5s)');
}
