import { Router, Request, Response } from 'express';
import { createIdentity, validateIdentity, killIdentity, regenerateIdentity } from '../services/identityService';
import { defensiveResponse, detectThreatEvent } from '../services/defensiveService';
import { updateHeartbeat } from '../services/heartbeat';
import { db } from '../config/database';
import { DefensiveAction } from '../models/Identity';
import paranoiaConfig from '../config/paranoia.json';

const router = Router();

/**
 * POST /identity/new
 */
router.post('/new', async (req: Request, res: Response) => {
  try {
    const { paranoiaLevel = 'medium' } = req.body;

    if (!['low', 'medium', 'high', 'deadman'].includes(paranoiaLevel)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid paranoia level. Must be: low, medium, high, or deadman'
      });
    }

    const result = await createIdentity(paranoiaLevel);

    res.json({
      success: true,
      message: '⚠️ SAVE YOUR PRIVATE KEY! It will never be shown again.',
      identity: result.identity,
      privateKey: result.privateKey
    });

  } catch (error) {
    console.error('[API] Error creating identity:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create identity'
    });
  }
});

/**
 * POST /identity/check
 * 🔥 CORRIGIDO: Sempre retorna 'action' + contadores corretos + usa totalAttempts para KILL
 */
router.post('/check', async (req: Request, res: Response) => {
  try {
    const { identityId, privateKey } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress || 'unknown';

    if (!identityId || !privateKey) {
      return res.status(400).json({
        success: false,
        error: 'identityId and privateKey are required'
      });
    }

    console.log(`\n[API] ========================================`);
    console.log(`[API] 🔍 Check from IP: ${clientIP}`);
    console.log(`[API] 🆔 Identity: ${identityId}`);

    let identity = await db.getIdentity(identityId);

    if (!identity || !identity.isAlive) {
      console.log(`[API] ❌ Identity not found or dead`);
      return res.status(404).json({
        success: false,
        action: 'KILLED',
        error: 'Invalid identity or private key'
      });
    }

    // 🔥 DEADMAN CHECK - Verificar se expirou ANTES de validar
    if (identity.paranoiaLevel === 'deadman') {
      const config = paranoiaConfig.deadman;
      const deadmanTimerMs = (config.deadmanTimer || 60) * 1000;
      const lastHeartbeat = identity.lastHeartbeat || identity.lastCheckIn || identity.createdAt;
      const timeSinceHeartbeat = Date.now() - lastHeartbeat;

      console.log(`[API] 💓 DEADMAN CHECK:`);
      console.log(`[API]    ├─ Last heartbeat: ${new Date(lastHeartbeat).toISOString()}`);
      console.log(`[API]    ├─ Time since: ${Math.floor(timeSinceHeartbeat / 1000)}s`);
      console.log(`[API]    └─ Timer limit: ${config.deadmanTimer}s`);

      if (timeSinceHeartbeat > deadmanTimerMs) {
        console.log(`[API] 💀 DEADMAN TIMER EXPIRED!`);
        console.log(`[API]    └─ Killing identity automatically...`);

        await killIdentity(identityId);

        return res.status(403).json({
          success: false,
          action: 'KILLED',
          error: 'Identity not found or already destroyed',
          reason: 'Deadman timer expired',
          timeSinceHeartbeat: Math.floor(timeSinceHeartbeat / 1000)
        });
      }
    }

    const config = paranoiaConfig[identity.paranoiaLevel];

    // 🔥 Inicializar contadores se não existirem
    if (typeof identity.totalAttempts === 'undefined') {
      identity.totalAttempts = identity.attempts;
    }
    if (typeof identity.regenerationCount === 'undefined') {
      identity.regenerationCount = 0;
    }
    if (typeof identity.attemptsAfterRegenerate === 'undefined') {
      identity.attemptsAfterRegenerate = 0;
    }

    console.log(`[API] 📊 Stats BEFORE validation:`);
    console.log(`[API]    ├─ Level: ${identity.paranoiaLevel}`);
    console.log(`[API]    ├─ Attempts: ${identity.attempts}/${config.maxAttempts}`);
    console.log(`[API]    ├─ Total: ${identity.totalAttempts}`);
    console.log(`[API]    ├─ Regenerations: ${identity.regenerationCount}`);
    console.log(`[API]    └─ After regenerate: ${identity.attemptsAfterRegenerate}`);

    const validatedIdentity = await validateIdentity(identityId, privateKey);

    if (validatedIdentity) {
      console.log(`[API] ✅ Validation SUCCESSFUL`);

      // 🔥 ATUALIZAR HEARTBEAT SE FOR DEADMAN
      if (identity.paranoiaLevel === 'deadman') {
        const now = Date.now();
        identity.lastHeartbeat = now;
        identity.lastCheckIn = now;
        console.log(`[API] 💓 Heartbeat auto-updated`);
      }

      // 🔥 Reset contadores em sucesso
      identity.attempts = 0;
      identity.attemptsAfterRegenerate = 0;
      await db.set(`identity:${identityId}`, identity);

      console.log(`[API] 🔄 Counters reset`);

      const timeSinceLastAttempt = Date.now() - validatedIdentity.lastAttemptAt;
      const threatEvent = detectThreatEvent(validatedIdentity, clientIP, timeSinceLastAttempt);
      const defensiveResult = await defensiveResponse(validatedIdentity, threatEvent, clientIP);

      console.log(`[API] 🎯 Action: ${defensiveResult.action}`);
      console.log(`[API] ========================================\n`);

      switch (defensiveResult.action) {
        case DefensiveAction.KILL:
          return res.status(403).json({
            success: false,
            action: 'KILLED',
            reason: defensiveResult.reason,
            message: '💀 Identity destroyed'
          });

        case DefensiveAction.REGENERATE:
          return res.json({
            success: true,
            action: 'REGENERATE',
            reason: defensiveResult.reason,
            message: '🔄 Identity regenerated',
            newIdentity: defensiveResult.newIdentity
          });

        case DefensiveAction.LIE:
          return res.json({
            success: true,
            action: 'LIE',
            reason: defensiveResult.reason,
            message: '🎭 Returning fake metadata',
            identity: defensiveResult.fakeData
          });

        case DefensiveAction.ALLOW:
        default:
          return res.json({
            success: true,
            action: 'ALLOWED',
            reason: defensiveResult.reason,
            identity: {
              id: defensiveResult.identity!.id,
              publicKey: defensiveResult.identity!.publicKey,
              paranoiaLevel: defensiveResult.identity!.paranoiaLevel,
              expiresAt: defensiveResult.identity!.expiresAt,
              attempts: defensiveResult.identity!.attempts,
              totalAttempts: defensiveResult.identity!.totalAttempts || 0
            }
          });
      }
    }

    // 🔥 VALIDAÇÃO FALHOU - Incrementar contadores ATOMICAMENTE
    console.log(`[API] ❌ Validation FAILED - Invalid private key`);

    // Recarregar identidade do Redis para garantir estado atual
    identity = await db.getIdentity(identityId);

    if (!identity) {
      return res.status(404).json({
        success: false,
        action: 'KILLED',
        error: 'Invalid identity or private key'
      });
    }

    // 🔥 INCREMENTO ATÔMICO DOS CONTADORES + TIMESTAMP
    identity.attempts = (identity.attempts || 0) + 1;
    identity.totalAttempts = (identity.totalAttempts || 0) + 1;
    identity.lastAttemptAt = Date.now();

    if (identity.regenerationCount > 0) {
      identity.attemptsAfterRegenerate = (identity.attemptsAfterRegenerate || 0) + 1;
    }

    // Salvar estado atualizado
    await db.set(`identity:${identityId}`, identity);

    console.log(`[API] 📈 Updated AFTER failed validation:`);
    console.log(`[API]    ├─ Attempts: ${identity.attempts}`);
    console.log(`[API]    ├─ Total: ${identity.totalAttempts}`);
    console.log(`[API]    ├─ Regenerations: ${identity.regenerationCount}`);
    console.log(`[API]    └─ After regenerate: ${identity.attemptsAfterRegenerate}`);

    // 🔥 LÓGICA DE KILL - CORRIGIDA PARA ATACANTE PERSISTENTE
    let shouldKill = false;
    let killReason = '';

    if (identity.regenerationCount > 0) {
      // Após regeneração: mata na 2ª tentativa falha
      shouldKill = identity.attemptsAfterRegenerate >= 2;
      killReason = `2nd failed attempt after regeneration (${identity.attemptsAfterRegenerate}/2)`;
    } else {
      // 🔥 CRÍTICO: Usar totalAttempts para bloquear atacante persistente
      // Atacante que faz 3+ tentativas (mesmo com UUIDs diferentes) é MORTO
      shouldKill = identity.totalAttempts >= config.maxAttempts;
      killReason = `Maximum total attempts exceeded (${identity.totalAttempts}/${config.maxAttempts})`;
    }

    if (shouldKill) {
      console.log(`[API] 💀 KILL TRIGGERED!`);
      console.log(`[API]    └─ Reason: ${killReason}`);

      await killIdentity(identityId);

      return res.status(403).json({
        success: false,
        action: 'KILLED',
        reason: killReason,
        message: '💀 Identity permanently destroyed',
        details: {
          attempts: identity.attempts,
          totalAttempts: identity.totalAttempts,
          maxAttempts: config.maxAttempts,
          regenerations: identity.regenerationCount,
          attemptsAfterRegenerate: identity.attemptsAfterRegenerate
        }
      });
    }

    // 🔥 LÓGICA DE LIE
    if (identity.regenerationCount > 0 && identity.attemptsAfterRegenerate === 1) {
      console.log(`[API] 🎭 LIE TRIGGERED!`);

      return res.status(401).json({
        success: false,
        action: 'LIE',
        reason: 'Suspicious activity after regeneration',
        message: '🎭 Fake data returned. Next failed attempt will KILL identity.',
        identity: {
          id: identity.id,
          publicKey: identity.publicKey,
          metadata: identity.fakeMetadata || {
            ip: '198.51.100.0',
            location: 'Unknown Location',
            userAgent: 'Mozilla/5.0 (Generic)',
            device: 'Unknown Device'
          }
        },
        warning: '⚠️ LAST CHANCE! Next failure = destruction.',
        attemptsAfterRegenerate: identity.attemptsAfterRegenerate,
        nextAction: 'KILL'
      });
    }

    // 🔥 LÓGICA DE REGENERATE
    if (identity.attempts >= config.regenerateThreshold && identity.regenerationCount === 0) {
      console.log(`[API] 🔄 REGENERATE TRIGGERED!`);

      await killIdentity(identityId);

      const newIdentityResult = await createIdentity(identity.paranoiaLevel);

      if (!newIdentityResult) {
        return res.status(500).json({
          success: false,
          action: 'ERROR',
          error: 'Failed to regenerate identity'
        });
      }

      const newIdentity = newIdentityResult.identity;
      newIdentity.totalAttempts = identity.totalAttempts;
      newIdentity.regenerationCount = (identity.regenerationCount || 0) + 1;
      newIdentity.attemptsAfterRegenerate = 0;
      await db.set(`identity:${newIdentity.id}`, newIdentity);

      return res.json({
        success: true,
        action: 'REGENERATE',
        reason: `Regenerated after ${identity.attempts} attempts`,
        message: '🔄 Identity regenerated. Old one destroyed.',
        warning: '⚠️ Next defense layers: LIE → KILL',
        details: {
          totalAttempts: identity.totalAttempts,
          maxAttempts: config.maxAttempts,
          regenerations: newIdentity.regenerationCount,
          remaining: config.maxAttempts - identity.totalAttempts
        },
        newIdentity: {
          id: newIdentity.id,
          publicKey: newIdentity.publicKey,
          privateKey: newIdentityResult.privateKey,
          paranoiaLevel: newIdentity.paranoiaLevel,
          expiresAt: newIdentity.expiresAt
        }
      });
    }

    // 🔥 ALLOW (tentativa registrada)
    const remaining = config.maxAttempts - identity.attempts;

    return res.status(401).json({
      success: false,
      action: 'ALLOWED',
      error: 'Invalid identity or private key',
      attempts: identity.attempts,
      totalAttempts: identity.totalAttempts,
      maxAttempts: config.maxAttempts,
      remaining: remaining,
      message: `Failed attempt logged. ${remaining} attempts remaining.`
    });

  } catch (error) {
    console.error('[API] ❌ Error:', error);
    res.status(500).json({
      success: false,
      action: 'ERROR',
      error: 'Failed to check identity'
    });
  }
});

/**
 * POST /identity/heartbeat
 */
router.post('/heartbeat', async (req: Request, res: Response) => {
  try {
    const { identityId, privateKey } = req.body;

    if (!identityId || !privateKey) {
      return res.status(400).json({
        success: false,
        error: 'identityId and privateKey are required'
      });
    }

    console.log(`[API] 💓 Heartbeat request for: ${identityId}`);

    const identity = await db.getIdentity(identityId);

    if (!identity || !identity.isAlive) {
      return res.status(404).json({
        success: false,
        error: 'Identity not found or already destroyed'
      });
    }

    const validatedIdentity = await validateIdentity(identityId, privateKey);

    if (!validatedIdentity) {
      return res.status(401).json({
        success: false,
        error: 'Invalid private key'
      });
    }

    if (identity.paranoiaLevel !== 'deadman') {
      return res.status(400).json({
        success: false,
        error: 'Heartbeat only available for DEADMAN level identities'
      });
    }

    const updated = await updateHeartbeat(identityId);

    if (!updated) {
      return res.status(500).json({
        success: false,
        error: 'Failed to update heartbeat'
      });
    }

    const config = paranoiaConfig.deadman;
    const now = Date.now();
    const nextDeadline = now + ((config.deadmanTimer || 60) * 1000);

    res.json({
      success: true,
      message: '💓 Heartbeat updated',
      identity: {
        id: identity.id,
        paranoiaLevel: identity.paranoiaLevel,
        lastHeartbeat: now,
        nextDeadline: nextDeadline,
        remainingSeconds: config.deadmanTimer
      }
    });

  } catch (error) {
    console.error('[API] Error in /heartbeat:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

/**
 * POST /identity/regenerate
 */
router.post('/regenerate', async (req: Request, res: Response) => {
  try {
    const { identityId, privateKey } = req.body;

    if (!identityId || !privateKey) {
      return res.status(400).json({
        success: false,
        error: 'identityId and privateKey are required'
      });
    }

    const validatedIdentity = await validateIdentity(identityId, privateKey);

    if (!validatedIdentity) {
      return res.status(401).json({
        success: false,
        error: 'Invalid identity or private key'
      });
    }

    const newIdentity = await regenerateIdentity(identityId);

    if (!newIdentity) {
      return res.status(500).json({
        success: false,
        error: 'Failed to regenerate identity'
      });
    }

    res.json({
      success: true,
      message: '🔄 Identity regenerated',
      identity: newIdentity.identity,
      privateKey: newIdentity.privateKey
    });

  } catch (error) {
    console.error('[API] Error regenerating:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to regenerate identity'
    });
  }
});

/**
 * POST /identity/kill
 */
router.post('/kill', async (req: Request, res: Response) => {
  try {
    const { identityId, privateKey } = req.body;

    if (!identityId || !privateKey) {
      return res.status(400).json({
        success: false,
        error: 'identityId and privateKey are required'
      });
    }

    const validatedIdentity = await validateIdentity(identityId, privateKey);

    if (!validatedIdentity) {
      return res.status(401).json({
        success: false,
        error: 'Invalid identity or private key'
      });
    }

    const killed = await killIdentity(identityId);

    if (!killed) {
      return res.status(500).json({
        success: false,
        error: 'Failed to destroy identity'
      });
    }

    res.json({
      success: true,
      message: '💀 Identity destroyed'
    });

  } catch (error) {
    console.error('[API] Error killing:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to destroy identity'
    });
  }
});

/**
 * GET /identity/status/:id
 */
router.get('/status/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const identity = await db.getIdentity(id);

    if (!identity || !identity.isAlive) {
      return res.status(404).json({
        exists: false,
        message: 'Identity not found or destroyed'
      });
    }

    const config = paranoiaConfig[identity.paranoiaLevel];

    res.json({
      exists: true,
      expiresAt: identity.expiresAt,
      paranoiaLevel: identity.paranoiaLevel,
      attempts: identity.attempts,
      totalAttempts: identity.totalAttempts || identity.attempts,
      maxAttempts: config.maxAttempts,
      regenerations: identity.regenerationCount || 0,
      attemptsAfterRegenerate: identity.attemptsAfterRegenerate || 0,
      remaining: config.maxAttempts - (identity.attempts || 0)
    });

  } catch (error) {
    console.error('[API] Error checking status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to check status'
    });
  }
});

export default router;
