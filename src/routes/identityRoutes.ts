import { Router, Request, Response } from 'express';
import { createIdentity, validateIdentity, killIdentity, regenerateIdentity } from '../services/identityService';
import { defensiveResponse, detectThreatEvent } from '../services/defensiveService';
import { updateHeartbeat } from '../services/heartbeat';
import { db } from '../config/database';
import { DefensiveAction } from '../models/Identity';
import { requireApiKey, checkIdentityCreationLimit } from '../middleware/auth';
import { safeLog, safeError } from '../utils/sanitize';
import paranoiaConfig from '../config/paranoia.json';
import { extractFeatures, trackEndpoint } from '../services/featureExtraction';
import { analyzeWithAI } from '../services/aiClient';
import { combineDecisionsV3, DecisionContext } from '../services/decisionEngine';
import { analyzeWithRailwayAI, convertToRailwayFeatures } from '../services/railwayAiClient';

const router = Router();

// ─────────────────────────────────────────────
//  POST /identity/new
// ─────────────────────────────────────────────
router.post('/new',
  requireApiKey,
  checkIdentityCreationLimit,
  async (req: Request, res: Response) => {
    try {
      const { paranoiaLevel = 'medium' } = req.body;

      if (!['low', 'medium', 'high', 'deadman'].includes(paranoiaLevel)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid paranoia level. Must be: low, medium, high, or deadman',
        });
      }

      const result = await createIdentity(paranoiaLevel);

      // ✅ privateKey vai APENAS na resposta HTTP desta rota — NUNCA em logs
      res.json({
        success:    true,
        message:    '⚠️ SAVE YOUR PRIVATE KEY! It will never be shown again.',
        identity: {
          id:           result.identity.id,
          publicKey:    result.identity.publicKey,
          paranoiaLevel: result.identity.paranoiaLevel,
          expiresAt:    result.identity.expiresAt,
        },
        privateKey: result.privateKey,
      });
    } catch (error) {
      safeError('[API] Error creating identity:', error);
      res.status(500).json({ success: false, error: 'Failed to create identity' });
    }
  }
);

// ─────────────────────────────────────────────
//  POST /identity/check
// ─────────────────────────────────────────────
router.post('/check', async (req: Request, res: Response) => {
  try {
    // ✅ SEGURO: privateKey extraída do body mas JAMAIS logada
    const { identityId, privateKey } = req.body;
    const clientIP  = req.ip || req.connection.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || '';

    if (!identityId || !privateKey) {
      return res.status(400).json({ success: false, error: 'identityId and privateKey are required' });
    }

    let identity = await db.getIdentity(identityId);

    if (!identity || !identity.isAlive) {
      return res.status(401).json({ success: false, error: 'Invalid identity or private key' });
    }

    if (identity.paranoiaLevel === 'deadman') {
      const config         = paranoiaConfig.deadman;
      const deadmanTimerMs = (config.deadmanTimer || 60) * 1000;
      const lastHeartbeat  = identity.lastHeartbeat || identity.lastCheckIn || identity.createdAt;
      const timeSince      = Date.now() - lastHeartbeat;

      if (timeSince > deadmanTimerMs) {
        await killIdentity(identityId);
        return res.status(403).json({ success: false, action: 'KILLED', error: 'Identity destroyed' });
      }
    }

    const config = paranoiaConfig[identity.paranoiaLevel];

    if (typeof identity.totalAttempts          === 'undefined') identity.totalAttempts          = identity.attempts;
    if (typeof identity.regenerationCount      === 'undefined') identity.regenerationCount      = 0;
    if (typeof identity.attemptsAfterRegenerate === 'undefined') identity.attemptsAfterRegenerate = 0;

    const features        = await extractFeatures(identity, clientIP, userAgent);
    await trackEndpoint(identityId, 'check');
    const aiAnalysis      = await analyzeWithAI(features);
    const railwayFeatures = convertToRailwayFeatures(features);
    const railwayAI       = await analyzeWithRailwayAI(railwayFeatures);
    const validatedIdentity = await validateIdentity(identityId, privateKey);

    if (!validatedIdentity) {
      return res.status(401).json({ success: false, error: 'Invalid identity or private key' });
    }

    const isValidSignature = validatedIdentity.isValidSignature;

    // ── ALLOWED ──────────────────────────────────────────────
    if (isValidSignature === true) {
      if (identity.paranoiaLevel === 'deadman') {
        const now = Date.now();
        identity.lastHeartbeat = now;
        identity.lastCheckIn   = now;
      }
      identity.attempts                = 0;
      identity.attemptsAfterRegenerate = 0;
      await db.set(`identity:${identityId}`, identity);

      return res.json({
        success: true,
        action:  'ALLOWED',
        identity: {
          id:           validatedIdentity.id,
          publicKey:    validatedIdentity.publicKey,
          paranoiaLevel: validatedIdentity.paranoiaLevel,
          expiresAt:    validatedIdentity.expiresAt,
        },
      });
    }

    // ── Falha de validação ────────────────────────────────────
    // FIX: reler do DB após validateIdentity para garantir estado fresco
    identity = await db.getIdentity(identityId);
    if (!identity) return res.status(401).json({ success: false, error: 'Invalid identity or private key' });

    // FIX: incrementar ANTES de avaliar as regras
    identity.attempts               = (identity.attempts || 0) + 1;
    identity.totalAttempts          = (identity.totalAttempts || 0) + 1;
    identity.lastAttemptAt          = Date.now();
    if (identity.regenerationCount > 0) {
      identity.attemptsAfterRegenerate = (identity.attemptsAfterRegenerate || 0) + 1;
    }
    await db.set(`identity:${identityId}`, identity);

    // FIX: regras em ordem de prioridade, sem if/else solto
    let ruleBasedAction: DefensiveAction = DefensiveAction.ALLOW;

    if (identity.regenerationCount > 0) {
      if (identity.attemptsAfterRegenerate >= 2) {
        ruleBasedAction = DefensiveAction.KILL;
      } else if (identity.attemptsAfterRegenerate === 1) {
        ruleBasedAction = DefensiveAction.LIE;
      }
    } else if (identity.attempts >= config.regenerateThreshold) {
      ruleBasedAction = DefensiveAction.REGENERATE;
    }

    // FIX: AI só pode AGRAVAR, nunca suavizar a regra local
    // Hierarquia: KILL > LIE > REGENERATE > ALLOW
    const actionPriority: Record<DefensiveAction, number> = {
      [DefensiveAction.KILL]:       4,
      [DefensiveAction.LIE]:        3,
      [DefensiveAction.REGENERATE]: 2,
      [DefensiveAction.ALLOW]:      1,
    };

    const aiRecommendation = aiAnalysis?.riskAnalysis.recommendedAction || DefensiveAction.ALLOW;
    const finalAction = actionPriority[aiRecommendation] > actionPriority[ruleBasedAction]
      ? aiRecommendation
      : ruleBasedAction;

    // ── KILL ─────────────────────────────────────────────────
    if (finalAction === DefensiveAction.KILL) {
      await killIdentity(identityId);
      return res.status(403).json({ success: false, action: 'KILLED', error: 'Identity destroyed' });
    }

    // ── LIE ──────────────────────────────────────────────────
    // intencional: engana o atacante retornando ALLOWED com falha
    if (finalAction === DefensiveAction.LIE) {
      return res.status(401).json({
        success: false,
        action:  'ALLOWED',
        error:   'Invalid identity or private key',
      });
    }

    // ── REGENERATE ───────────────────────────────────────────
    if (finalAction === DefensiveAction.REGENERATE) {
      await killIdentity(identityId);
      const newIdentityResult = await createIdentity(identity.paranoiaLevel);

      if (!newIdentityResult) {
        return res.status(500).json({ success: false, error: 'Failed to regenerate identity' });
      }

      const newIdentity                    = newIdentityResult.identity;
      newIdentity.totalAttempts            = identity.totalAttempts;
      newIdentity.regenerationCount        = (identity.regenerationCount || 0) + 1;
      newIdentity.attemptsAfterRegenerate  = 0;
      await db.set(`identity:${newIdentity.id}`, newIdentity);

      // ✅ privateKey retornada na resposta — NUNCA em logs
      return res.json({
        success: true,
        action:  'REGENERATE',
        identity: {
          id:           newIdentity.id,
          publicKey:    newIdentity.publicKey,
          paranoiaLevel: newIdentity.paranoiaLevel,
          expiresAt:    newIdentity.expiresAt,
        },
        privateKey: newIdentityResult.privateKey,
      });
    }

    // ── ALLOW (falha simples) ─────────────────────────────────
    return res.status(401).json({
      success: false,
      action:  'ALLOWED',
      error:   'Invalid identity or private key',
    });

  } catch (error) {
    safeError('[API] ❌ Error in /check:', error);
    res.status(500).json({ success: false, error: 'Failed to check identity' });
  }
});

// ─────────────────────────────────────────────
//  POST /identity/heartbeat
// ─────────────────────────────────────────────
router.post('/heartbeat', async (req: Request, res: Response) => {
  try {
    const { identityId, privateKey } = req.body;

    if (!identityId || !privateKey) {
      return res.status(400).json({ success: false, error: 'identityId and privateKey are required' });
    }

    const identity = await db.getIdentity(identityId);

    if (!identity || !identity.isAlive) {
      return res.status(401).json({ success: false, error: 'Invalid identity or private key' });
    }

    const validatedIdentity = await validateIdentity(identityId, privateKey);

    if (!validatedIdentity || !validatedIdentity.isValidSignature) {
      return res.status(401).json({ success: false, error: 'Invalid private key' });
    }

    if (identity.paranoiaLevel !== 'deadman') {
      return res.status(400).json({ success: false, error: 'Invalid request' });
    }

    const updated = await updateHeartbeat(identityId);

    if (!updated) {
      return res.status(500).json({ success: false, error: 'Failed to update heartbeat' });
    }

    const config       = paranoiaConfig.deadman;
    const now          = Date.now();
    const nextDeadline = now + ((config.deadmanTimer || 60) * 1000);

    res.json({
      success: true,
      identity: {
        id:              identity.id,
        paranoiaLevel:   identity.paranoiaLevel,
        nextDeadline,
        remainingSeconds: config.deadmanTimer,
      },
    });

  } catch (error) {
    safeError('[API] Error in /heartbeat:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────
//  POST /identity/regenerate
// ─────────────────────────────────────────────
router.post('/regenerate', async (req: Request, res: Response) => {
  try {
    const { identityId, privateKey } = req.body;

    if (!identityId || !privateKey) {
      return res.status(400).json({ success: false, error: 'identityId and privateKey are required' });
    }

    const validatedIdentity = await validateIdentity(identityId, privateKey);

    if (!validatedIdentity || !validatedIdentity.isValidSignature) {
      return res.status(401).json({ success: false, error: 'Invalid identity or private key' });
    }

    const newIdentity = await regenerateIdentity(identityId);

    if (!newIdentity) {
      return res.status(500).json({ success: false, error: 'Failed to regenerate identity' });
    }

    // ✅ privateKey retornada na resposta — NUNCA em logs
    res.json({
      success: true,
      identity: {
        id:           newIdentity.identity.id,
        publicKey:    newIdentity.identity.publicKey,
        paranoiaLevel: newIdentity.identity.paranoiaLevel,
        expiresAt:    newIdentity.identity.expiresAt,
      },
      privateKey: newIdentity.privateKey,
    });

  } catch (error) {
    safeError('[API] Error regenerating:', error);
    res.status(500).json({ success: false, error: 'Failed to regenerate identity' });
  }
});

// ─────────────────────────────────────────────
//  POST /identity/kill
// ─────────────────────────────────────────────
router.post('/kill', async (req: Request, res: Response) => {
  try {
    const { identityId, privateKey } = req.body;

    if (!identityId || !privateKey) {
      return res.status(400).json({ success: false, error: 'identityId and privateKey are required' });
    }

    const validatedIdentity = await validateIdentity(identityId, privateKey);

    if (!validatedIdentity || !validatedIdentity.isValidSignature) {
      return res.status(401).json({ success: false, error: 'Invalid identity or private key' });
    }

    const killed = await killIdentity(identityId);

    if (!killed) {
      return res.status(500).json({ success: false, error: 'Failed to destroy identity' });
    }

    res.json({ success: true });

  } catch (error) {
    safeError('[API] Error killing:', error);
    res.status(500).json({ success: false, error: 'Failed to destroy identity' });
  }
});

// ─────────────────────────────────────────────
//  GET /identity/status/:id
// ─────────────────────────────────────────────
router.get('/status/:id', async (req: Request, res: Response) => {
  try {
    const { id }   = req.params;
    const identity = await db.getIdentity(id);

    if (!identity || !identity.isAlive) {
      return res.status(404).json({ exists: false });
    }

    res.json({
      exists:       true,
      paranoiaLevel: identity.paranoiaLevel,
      expiresAt:    identity.expiresAt,
    });

  } catch (error) {
    safeError('[API] Error checking status:', error);
    res.status(500).json({ success: false, error: 'Failed to check status' });
  }
});

export default router;