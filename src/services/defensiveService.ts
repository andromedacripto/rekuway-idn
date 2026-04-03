import { Identity, ThreatEvent, DefensiveAction } from '../models/Identity';
import { db } from '../config/database';
import { safeLog, safeError } from '../utils/sanitize';
import paranoiaConfig from '../config/paranoia.json';
import { killIdentity, regenerateIdentity } from './identityService';

export interface DefensiveResponse {
  action: DefensiveAction;
  reason: string;
  identity: Identity | null;
  fakeData?: any;
  newIdentity?: { identity: Identity; privateKey: string };
}

/**
 * 🔒 LOCK REDIS ATÔMICO V2
 */
async function acquireLock(identityId: string, timeoutMs = 5000): Promise<boolean> {
  const lockKey   = `lock:${identityId}`;
  const lockValue = `${Date.now()}`;
  const ttlSeconds = Math.ceil(timeoutMs / 1000);

  try {
    const existing = await db.get(lockKey);

    if (!existing) {
      await db.set(lockKey, lockValue, ttlSeconds);
      await new Promise(resolve => setTimeout(resolve, 10));
      const current = await db.get(lockKey);

      if (current === lockValue) {
        safeLog(`[LOCK] ✅ Acquired:`, { id: identityId });
        return true;
      }
      safeLog(`[LOCK] ❌ Lost race:`, { id: identityId });
      return false;
    }

    const lockAge = Date.now() - parseInt(existing as string, 10);
    if (lockAge > timeoutMs) {
      safeLog(`[LOCK] 🔓 Stale lock released:`, { id: identityId, lockAgeMs: lockAge });
      await db.delete(lockKey);
      return acquireLock(identityId, timeoutMs);
    }

    safeLog(`[LOCK] ⏳ Lock held:`, { id: identityId, lockAgeMs: lockAge });
    return false;
  } catch (error) {
    safeError('[LOCK] ⚠️ Error acquiring lock:', error);
    return false;
  }
}

async function releaseLock(identityId: string): Promise<void> {
  try {
    await db.delete(`lock:${identityId}`);
    safeLog(`[LOCK] 🔓 Released:`, { id: identityId });
  } catch (error) {
    safeError('[LOCK] Error releasing lock:', error);
  }
}

export async function defensiveResponse(
  identity: Identity,
  event: ThreatEvent,
  clientIP: string
): Promise<DefensiveResponse> {
  let lockAcquired = false;
  let retries = 3;

  while (!lockAcquired && retries > 0) {
    lockAcquired = await acquireLock(identity.id, 5000);
    if (!lockAcquired) {
      retries--;
      if (retries > 0) {
        safeLog(`[LOCK] 🔄 Retrying...`, { retriesLeft: retries });
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
  }

  if (!lockAcquired) {
    safeLog(`[DEFENSE] ⚠️ Lock timeout — possible concurrent access`, { id: identity.id });

    const concurrentKey   = `concurrent:${identity.id}`;
    const concurrentCount = (((await db.get(concurrentKey)) as number) || 0) + 1;
    await db.set(concurrentKey, concurrentCount, 3600);

    safeLog(`[DEFENSE] Concurrent count:`, { id: identity.id, count: concurrentCount });

    if (concurrentCount >= 5) {
      safeLog(`[DEFENSE] 🚨 Malicious parallel attack:`, { id: identity.id, count: concurrentCount });

      const freshIdentity = await db.getIdentity(identity.id);
      if (freshIdentity && freshIdentity.isAlive) {
        freshIdentity.attempts      = (freshIdentity.attempts || 0) + 5;
        freshIdentity.totalAttempts = (freshIdentity.totalAttempts || 0) + 5;
        await db.setIdentity(freshIdentity.id, freshIdentity);
        await killIdentity(identity.id);

        return {
          action: DefensiveAction.KILL,
          reason: `Parallel attack detected: ${concurrentCount} concurrent attempts`,
          identity: null,
        };
      }
    }

    return {
      action: DefensiveAction.ALLOW,
      reason: `Concurrent access within tolerance (${concurrentCount}/5)`,
      identity,
    };
  }

  try {
    const freshIdentity = await db.getIdentity(identity.id);

    if (!freshIdentity || !freshIdentity.isAlive) {
      return { action: DefensiveAction.KILL, reason: 'Identity no longer exists or already killed', identity: null };
    }

    const config = paranoiaConfig[freshIdentity.paranoiaLevel];

    if (!freshIdentity.suspiciousIPs.includes(clientIP)) {
      freshIdentity.suspiciousIPs.push(clientIP);
      await db.setIdentity(freshIdentity.id, freshIdentity);
    }

    // ✅ SEGURO: loga apenas métricas, sem dados sensíveis
    safeLog(`[DEFENSE] 🎯 Analysis:`, {
      id:           freshIdentity.id,
      event,
      attempts:     freshIdentity.attempts,
      maxAttempts:  config.maxAttempts,
      total:        freshIdentity.totalAttempts || 0,
      regenerations: freshIdentity.regenerationCount || 0,
    });

    if (freshIdentity.attempts >= config.maxAttempts) {
      safeLog(`[DEFENSE] 💀 KILL: maxAttempts exceeded`, { id: freshIdentity.id });
      await killIdentity(freshIdentity.id);
      return {
        action: DefensiveAction.KILL,
        reason: `Maximum attempts exceeded (${freshIdentity.attempts}/${config.maxAttempts})`,
        identity: null,
      };
    }

    if (freshIdentity.totalAttempts && freshIdentity.totalAttempts >= config.maxAttempts) {
      safeLog(`[DEFENSE] 💀 KILL: persistent attacker`, {
        id:    freshIdentity.id,
        total: freshIdentity.totalAttempts,
      });
      await killIdentity(freshIdentity.id);
      return {
        action: DefensiveAction.KILL,
        reason: `Persistent attacker (${freshIdentity.totalAttempts} total attempts)`,
        identity: null,
      };
    }

    if (freshIdentity.regenerationCount && freshIdentity.regenerationCount > 0) {
      const attemptsAfterRegen = freshIdentity.attemptsAfterRegenerate || 0;

      if (attemptsAfterRegen === 1) {
        safeLog(`[DEFENSE] 🎭 LIE: suspicious after regeneration`, { id: freshIdentity.id });
        return {
          action: DefensiveAction.LIE,
          reason: 'Suspicious activity after regeneration — returning fake metadata',
          identity: freshIdentity,
          fakeData: freshIdentity.fakeMetadata,
        };
      }

      if (attemptsAfterRegen >= 2) {
        safeLog(`[DEFENSE] 💀 KILL: 2nd attempt after regeneration`, { id: freshIdentity.id });
        await killIdentity(freshIdentity.id);
        return {
          action: DefensiveAction.KILL,
          reason: 'Second failed attempt after regeneration',
          identity: null,
        };
      }
    }

    if (config.regenerateThreshold && freshIdentity.attempts >= config.regenerateThreshold) {
      if (!freshIdentity.regenerationCount || freshIdentity.regenerationCount === 0) {
        safeLog(`[DEFENSE] 🔄 REGENERATE: threshold reached`, {
          id:       freshIdentity.id,
          attempts: freshIdentity.attempts,
          threshold: config.regenerateThreshold,
        });
        const newIdentity = await regenerateIdentity(freshIdentity.id);
        return {
          action: DefensiveAction.REGENERATE,
          reason: `Identity regenerated: exceeded ${config.regenerateThreshold} suspicious attempts`,
          identity: null,
          newIdentity: newIdentity || undefined,
        };
      }
    }

    if (config.fakeFingerprintEnabled && event === ThreatEvent.FINGERPRINT_MATCH) {
      safeLog(`[DEFENSE] 🎭 LIE: fingerprint match`, { id: freshIdentity.id });
      return {
        action: DefensiveAction.LIE,
        reason: 'Fingerprint match — returning fake metadata',
        identity: freshIdentity,
        fakeData: freshIdentity.fakeMetadata,
      };
    }

    safeLog(`[DEFENSE] ✅ ALLOW`, { id: freshIdentity.id });
    return {
      action: DefensiveAction.ALLOW,
      reason: 'Event logged but within acceptable threshold',
      identity: freshIdentity,
    };

  } catch (error) {
    safeError('[DEFENSE] ❌ Error in defensive response:', error);
    await killIdentity(identity.id);
    return {
      action: DefensiveAction.KILL,
      reason: 'Identity killed due to system error (fail-safe)',
      identity: null,
    };
  } finally {
    await releaseLock(identity.id);
  }
}

export function detectThreatEvent(
  identity: Identity,
  clientIP: string,
  timeSinceLastAttempt: number
): ThreatEvent {
  if (timeSinceLastAttempt < 5000 && identity.attempts > 0) {
    safeLog(`[THREAT] 🔴 BRUTE_FORCE:`, { intervalMs: timeSinceLastAttempt });
    return ThreatEvent.BRUTE_FORCE;
  }
  if (identity.attempts > 10 && timeSinceLastAttempt < 60000) {
    safeLog(`[THREAT] 🔴 RATE_LIMIT:`, { attempts: identity.attempts });
    return ThreatEvent.RATE_LIMIT;
  }
  if (identity.suspiciousIPs.includes(clientIP)) {
    safeLog(`[THREAT] 🟡 FINGERPRINT_MATCH`);
    return ThreatEvent.FINGERPRINT_MATCH;
  }
  if (identity.attempts > 5) {
    safeLog(`[THREAT] 🟢 SCRAPING:`, { attempts: identity.attempts });
    return ThreatEvent.SCRAPING;
  }
  return ThreatEvent.RATE_LIMIT;
}

export async function checkDeadmanSwitch(identity: Identity): Promise<boolean> {
  if (identity.paranoiaLevel !== 'deadman') return false;

  const config            = paranoiaConfig.deadman;
  const now               = Date.now();
  const lastHeartbeat     = identity.lastHeartbeat || identity.lastCheckIn || identity.createdAt;
  const timeSinceHeartbeat = now - lastHeartbeat;
  const deadmanTimerMs    = (config.deadmanTimer || 60) * 1000;

  safeLog(`[DEADMAN] 💓 Checking:`, {
    id:                identity.id,
    lastHeartbeat:     new Date(lastHeartbeat).toISOString(),
    timeSinceSec:      Math.floor(timeSinceHeartbeat / 1000),
    timerLimitSec:     config.deadmanTimer,
  });

  if (timeSinceHeartbeat > deadmanTimerMs) {
    safeLog(`[DEADMAN] 💀 Timeout exceeded — KILLING:`, { id: identity.id });
    await killIdentity(identity.id);
    return true;
  }

  return false;
}

export function startDeadmanMonitor() {
  safeLog('[DEADMAN] 🚀 Starting Deadman Monitor...');

  setInterval(async () => {
    try {
      const identities = await db.listIdentities();
      let checked = 0;
      let killed  = 0;

      for (const identity of identities) {
        if (identity.paranoiaLevel === 'deadman' && identity.isAlive) {
          checked++;
          const wasKilled = await checkDeadmanSwitch(identity);
          if (wasKilled) {
            killed++;
            safeLog(`[DEADMAN] 💀 Killed by timeout:`, { id: identity.id });
          }
        }
      }

      if (checked > 0) {
        safeLog(`[DEADMAN] Sweep complete:`, { checked, killed });
      }
    } catch (error) {
      safeError('[DEADMAN] Monitor error:', error);
    }
  }, 5000);

  safeLog('[DEADMAN] ✅ Monitor started (every 5s)');
}
