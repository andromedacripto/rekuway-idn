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
  try {
    // Pega configurações do nível de paranoia
    const config = paranoiaConfig[identity.paranoiaLevel];

    // ❌ REMOVIDO: identity.attempts++; 
    // O incremento já foi feito no identityService quando a validação falhou

    // Adiciona IP suspeito se não estiver na lista
    if (!identity.suspiciousIPs.includes(clientIP)) {
      identity.suspiciousIPs.push(clientIP);
      await db.setIdentity(identity.id, identity);
    }

    console.log(`[DEFENSE] Event: ${event} | Identity: ${identity.id} | Attempts: ${identity.attempts}/${config.maxAttempts}`);

    // DECISÃO 1: KILL (prioridade máxima)
    // Mata após 3 tentativas erradas (maxAttempts)
    if (identity.attempts >= config.maxAttempts) {
      await killIdentity(identity.id);
      
      return {
        action: DefensiveAction.KILL,
        reason: `Too many failed attempts (${identity.attempts}/${config.maxAttempts})`,
        identity: null
      };
    }

    // DECISÃO 2: REGENERATE
    if (config.regenerateThreshold && identity.attempts >= config.regenerateThreshold) {
      const newIdentity = await regenerateIdentity(identity.id);
      
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
        identity: identity,
        fakeData: identity.fakeMetadata
      };
    }

    // DECISÃO 4: ALLOW (permitir mas com warning)
    return {
      action: DefensiveAction.ALLOW,
      reason: 'Event logged but within acceptable threshold',
      identity: identity
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
  const timeSinceHeartbeat = now - (identity.lastHeartbeat || identity.createdAt);
  
  // Se passou do tempo sem heartbeat, mata
  if (config.deadmanTimer && timeSinceHeartbeat > config.deadmanTimer * 1000) {
    console.log(`[DEADMAN] ⚠️ Timeout exceeded for identity ${identity.id}`);
    await killIdentity(identity.id);
    return true;
  }

  return false;
}

/**
 * Background job que verifica deadman switches
 * Roda a cada 10 segundos
 */
export function startDeadmanMonitor() {
  setInterval(async () => {
    try {
      const identities = await db.listIdentities();
      
      for (const identity of identities) {
        if (identity.paranoiaLevel === 'deadman' && identity.isAlive) {
          await checkDeadmanSwitch(identity);
        }
      }
    } catch (error) {
      console.error('[DEADMAN] Monitor error:', error);
    }
  }, 10000); // 10 segundos

  console.log('[DEADMAN] Monitor started');
}