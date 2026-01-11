/**
 * 💓 DEADMAN HEARTBEAT MONITOR
 * 
 * Monitora identidades DEADMAN e auto-destrói
 * se não receberem heartbeat dentro do timer configurado
 */

import { db } from '../config/database';
import { Identity } from '../models/Identity';
import paranoiaConfig from '../config/paranoia.json';
import { killIdentity } from './identityService';

/**
 * Verifica todas as identidades DEADMAN e mata as que expiraram
 */
export async function checkDeadmanTimers(): Promise<void> {
  try {
    console.log('[DEADMAN] 🕐 Checking heartbeat timers...');

    const keys = await db.keys('identity:*');
    
    if (!keys || keys.length === 0) {
      console.log('[DEADMAN] No identities to check.');
      return;
    }

    const now = Date.now();
    let killedCount = 0;
    let checkedCount = 0;

    for (const key of keys) {
      try {
        const identity = await db.get(key) as Identity | null;
        
        if (!identity || !identity.isAlive) continue;
        if (identity.paranoiaLevel !== 'deadman') continue;

        checkedCount++;

        const config = paranoiaConfig.deadman;
        const deadmanTimerMs = (config.deadmanTimer || 60) * 1000;

        const lastHeartbeat = identity.lastHeartbeat || identity.lastCheckIn || identity.createdAt;
        const timeSinceHeartbeat = now - lastHeartbeat;

        if (timeSinceHeartbeat > deadmanTimerMs) {
          console.log(`[DEADMAN] 💀 KILLING identity ${identity.id}`);
          console.log(`[DEADMAN]    ├─ No heartbeat for: ${Math.floor(timeSinceHeartbeat / 1000)}s`);
          console.log(`[DEADMAN]    └─ Reason: Deadman timer expired`);
          
          await killIdentity(identity.id);

          const eventKey = `event:${now}:${identity.id}`;
          await db.set(eventKey, {
            timestamp: new Date(now).toISOString(),
            action: 'KILLED',
            identityId: identity.id,
            reason: 'Deadman timer expired',
            timeSinceHeartbeat: Math.floor(timeSinceHeartbeat / 1000)
          }, 3600);

          killedCount++;
        } else {
          const remainingSeconds = Math.floor((deadmanTimerMs - timeSinceHeartbeat) / 1000);
          console.log(`[DEADMAN] ⏳ Identity ${identity.id.substring(0, 8)}... - ${remainingSeconds}s remaining`);
        }

      } catch (err) {
        console.error(`[DEADMAN] Error checking ${key}:`, err);
      }
    }

    if (killedCount > 0) {
      console.log(`[DEADMAN] 💀 Killed ${killedCount} expired identities`);
    } else if (checkedCount > 0) {
      console.log(`[DEADMAN] ✅ All ${checkedCount} DEADMAN identities healthy`);
    }

  } catch (error) {
    console.error('[DEADMAN] Error:', error);
  }
}

/**
 * Inicia monitor de deadman switches (executa a cada 10 segundos)
 */
export function startDeadmanMonitor(): void {
  console.log('[DEADMAN] 🚀 Starting monitor (10s interval)...');
  
  checkDeadmanTimers();

  const interval = setInterval(() => {
    checkDeadmanTimers();
  }, 10000);

  if (interval.unref) {
    interval.unref();
  }

  console.log('[DEADMAN] 💓 Monitor ACTIVE!');
}

/**
 * Atualiza heartbeat de uma identidade DEADMAN
 */
export async function updateHeartbeat(identityId: string): Promise<boolean> {
  try {
    const key = `identity:${identityId}`;
    const identity = await db.get(key) as Identity | null;

    if (!identity || !identity.isAlive) {
      console.log(`[DEADMAN] ❌ Identity not found or dead`);
      return false;
    }

    if (identity.paranoiaLevel !== 'deadman') {
      console.log(`[DEADMAN] ⚠️ Not a DEADMAN identity`);
      return false;
    }

    const now = Date.now();
    identity.lastHeartbeat = now;
    identity.lastCheckIn = now;

    await db.set(key, identity);

    console.log(`[DEADMAN] 💓 Heartbeat updated for ${identityId}`);
    return true;

  } catch (error) {
    console.error(`[DEADMAN] Error updating heartbeat:`, error);
    return false;
  }
}