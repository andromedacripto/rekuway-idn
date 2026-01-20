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
 * 🔒 LOCK REDIS - Previne race conditions em ataques paralelos
 * Usa Redis SETNX (Set if Not Exists) para garantir atomicidade
 */
async function acquireLock(identityId: string, timeoutMs: number = 5000): Promise<boolean> {
  const lockKey = `lock:${identityId}`;
  const lockValue = Date.now().toString();
  
  try {
    // 🔥 CORRIGIDO: Usar API correta do Upstash Redis
    const result = await db.set(lockKey, lockValue, timeoutMs);
    
    // Se conseguiu setar, adquiriu o lock
    return result !== null;
  } catch (error) {
    console.error('[LOCK] Error acquiring lock:', error);
    return false;
  }
}

async function releaseLock(identityId: string): Promise<void> {
  const lockKey = `lock:${identityId}`;
  try {
    // 🔥 CORRIGIDO: Usar delete ao invés de del
    await db.delete(lockKey);
  } catch (error) {
    console.error('[LOCK] Error releasing lock:', error);
  }
}

/**
 * FUNÇÃO PRINCIPAL: Analisa evento e decide ação defensiva
 *
 * Esta é a inteligência do sistema. Ela:
 * 1. Detecta o tipo de ameaça
 * 2. Consulta as configurações de paranoia
 * 3. Decide se: permite, mente, regenera ou mata
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
  // 🔒 CRÍTICO: Adquirir lock para prevenir race conditions
  const lockAcquired = await acquireLock(identity.id, 5000);
  
  if (!lockAcquired) {
    console.log(`[DEFENSE] ⚠️ Lock timeout - concurrent access detected for ${identity.id}`);
    // Em caso de race condition, assume postura defensiva
    await killIdentity(identity.id);
    return {
      action: DefensiveAction.KILL,
      reason: 'Race condition detected - concurrent access blocked',
      identity: null
    };
  }

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

    console.log(`[DEFENSE] Event: ${event} | Identity: ${freshIdentity.id} | Attempts: ${freshIdentity.attempts}/${config.maxAttempts}`);

    // DECISÃO 1: KILL (prioridade máxima)
    // Mata após maxAttempts tentativas erradas
    if (freshIdentity.attempts >= config.maxAttempts) {
      await killIdentity(freshIdentity.id);

      return {
        action: DefensiveAction.KILL,
        reason: `Too many failed attempts (${freshIdentity.attempts}/${config.maxAttempts})`,
        identity: null
      };
    }

    // DECISÃO 2: REGENERATE
    if (config.regenerateThreshold && freshIdentity.attempts >= config.regenerateThreshold) {
      const newIdentity = await regenerateIdentity(freshIdentity.id);

      return {
        action: DefensiveAction.REGENERATE,
        reason: `Identity regenerated: exceeded ${config.regenerateThreshold} suspicious attempts`,
        identity: null,
        newIdentity: newIdentity || undefined
      };
    }

    // DECISÃO 3: LIE (retornar dados falsos)
    if (config.fakeFingerprintEnabled && event === ThreatEvent.FINGERPRINT_MATCH) {
      return {
        action: DefensiveAction.LIE,
        reason: 'Fingerprint match detected: returning fake metadata',
        identity: freshIdentity,
        fakeData: freshIdentity.fakeMetadata
      };
    }

    // DECISÃO 4: ALLOW (permitir mas com warning)
    return {
      action: DefensiveAction.ALLOW,
      reason: 'Event logged but within acceptable threshold',
      identity: freshIdentity
    };

  } catch (error) {
    console.error('[DEFENSE] Error in defensive response:', error);

    // Em caso de erro, assume postura defensiva
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
  // Brute force: múltiplas tentativas em menos de 5 segundos
  if (timeSinceLastAttempt < 5000 && identity.attempts > 0) {
    return ThreatEvent.BRUTE_FORCE;
  }

  // Rate limit: mais de 10 tentativas em 1 minuto
  if (identity.attempts > 10 && timeSinceLastAttempt < 60000) {
    return ThreatEvent.RATE_LIMIT;
  }

  // Fingerprint match: mesmo IP tentando novamente
  if (identity.suspiciousIPs.includes(clientIP)) {
    return ThreatEvent.FINGERPRINT_MATCH;
  }

  // Scraping: padrão de requisições automáticas
  if (identity.attempts > 5) {
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

  console.log(`[DEADMAN] Checking identity ${identity.id}:`);
  console.log(`[DEADMAN]   ├─ Last heartbeat: ${new Date(lastHeartbeat).toISOString()}`);
  console.log(`[DEADMAN]   ├─ Time since: ${Math.floor(timeSinceHeartbeat / 1000)}s`);
  console.log(`[DEADMAN]   └─ Timer limit: ${config.deadmanTimer}s`);

  // Se passou do tempo sem heartbeat, mata
  if (timeSinceHeartbeat > deadmanTimerMs) {
    console.log(`[DEADMAN] ⚠️ Timeout exceeded for identity ${identity.id} - KILLING NOW`);
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