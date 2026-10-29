/**
 * 💓 DEADMAN HEARTBEAT MONITOR — REKUWAY IDN
 * Logs sanitizados: nunca expõe privateKey, apiKey ou secrets.
 */

import { db } from '../config/database';
import { Identity } from '../models/Identity';
import { safeLog, safeError } from '../utils/sanitize';
import paranoiaConfig from '../config/paranoia.json';
import { killIdentity } from './identityService';

export async function checkDeadmanTimers(): Promise<void> {
  try {
    const keys = await db.keys('identity:*');
    if (!keys || keys.length === 0) return;

    const now = Date.now();
    let killedCount = 0;
    let checkedCount = 0;

    for (const key of keys) {
      try {
        const identity = (await db.get(key)) as Identity | null;
        if (!identity || !identity.isAlive || identity.paranoiaLevel !== 'deadman') continue;

        checkedCount++;

        const config = paranoiaConfig.deadman;
        const deadmanTimerMs = (config.deadmanTimer || 60) * 1000;
        const lastHeartbeat = identity.lastHeartbeat || identity.lastCheckIn || identity.createdAt;
        const timeSinceHeartbeat = now - lastHeartbeat;

        if (timeSinceHeartbeat > deadmanTimerMs) {
          safeLog(`[DEADMAN] 💀 KILLING:`, {
            id: identity.id,
            timeSinceSec: Math.floor(timeSinceHeartbeat / 1000),
            reason: 'Deadman timer expired',
          });

          await killIdentity(identity.id);

          await db.set(
            `event:${now}:${identity.id}`,
            {
              timestamp: new Date(now).toISOString(),
              action: 'KILLED',
              identityId: identity.id,
              reason: 'Deadman timer expired',
              timeSinceHeartbeat: Math.floor(timeSinceHeartbeat / 1000),
            },
            3600
          );

          killedCount++;
        } else {
          const remainingSec = Math.floor((deadmanTimerMs - timeSinceHeartbeat) / 1000);
          safeLog(`[DEADMAN] ⏳ Alive:`, {
            id: identity.id.substring(0, 8) + '...',
            remainingSec,
          });
        }
      } catch (err) {
        safeError(`[DEADMAN] Error checking key ${key}:`, err);
      }
    }

    if (killedCount > 0) {
      safeLog(`[DEADMAN] 💀 Killed:`, { count: killedCount });
    } else if (checkedCount > 0) {
      safeLog(`[DEADMAN] ✅ All healthy:`, { count: checkedCount });
    }
  } catch (error) {
    safeError('[DEADMAN] Error:', error);
  }
}

export function startDeadmanMonitor(): void {
  safeLog('[DEADMAN] 🚀 Starting monitor (10s interval)...');
  checkDeadmanTimers();

  const interval = setInterval(() => {
    checkDeadmanTimers();
  }, 10000);
  if (interval.unref) interval.unref();

  safeLog('[DEADMAN] 💓 Monitor ACTIVE!');
}

export async function updateHeartbeat(identityId: string): Promise<boolean> {
  try {
    const key = `identity:${identityId}`;
    const identity = (await db.get(key)) as Identity | null;

    if (!identity || !identity.isAlive) {
      safeLog(`[DEADMAN] ❌ Identity not found or dead:`, { id: identityId });
      return false;
    }

    if (identity.paranoiaLevel !== 'deadman') {
      safeLog(`[DEADMAN] ⚠️ Not a DEADMAN identity:`, { id: identityId });
      return false;
    }

    const now = Date.now();
    identity.lastHeartbeat = now;
    identity.lastCheckIn = now;

    await db.set(key, identity);

    safeLog(`[DEADMAN] 💓 Heartbeat updated:`, { id: identityId });
    return true;
  } catch (error) {
    safeError(`[DEADMAN] Error updating heartbeat:`, error);
    return false;
  }
}
