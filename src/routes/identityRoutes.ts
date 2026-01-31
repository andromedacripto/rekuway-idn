import { Router, Request, Response } from 'express';
import { createIdentity, validateIdentity, killIdentity, regenerateIdentity } from '../services/identityService';
import { defensiveResponse, detectThreatEvent } from '../services/defensiveService';
import { updateHeartbeat } from '../services/heartbeat';
import { db } from '../config/database';
import { DefensiveAction } from '../models/Identity';
import { requireApiKey, checkIdentityCreationLimit } from '../middleware/auth';
import paranoiaConfig from '../config/paranoia.json';
import { extractFeatures, trackEndpoint } from '../services/featureExtraction';
import { analyzeWithAI } from '../services/aiClient';
import { combineDecisionsV3, DecisionContext } from '../services/decisionEngine';

const router = Router();

router.post('/new',
  requireApiKey,
  checkIdentityCreationLimit,
  async (req: Request, res: Response) => {
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

router.post('/check', async (req: Request, res: Response) => {
  try {
    const { identityId, privateKey } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || '';

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

    // ✅ CORREÇÃO #1: NÃO retorna KILL se identity não existe
    // Apenas retorna 404 genérico
    if (!identity) {
      console.log(`[API] ❌ Identity not found: ${identityId}`);
      return res.status(404).json({
        success: false,
        error: 'Identity not found'
      });
    }

    // ✅ CORREÇÃO #2: Verifica se está morta ANTES de processar
    if (!identity.isAlive) {
      console.log(`[API] ❌ Identity already dead: ${identityId}`);
      return res.status(403).json({
        success: false,
        action: 'KILLED',
        error: 'Identity was previously destroyed'
      });
    }

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
        
        // ✅ CORREÇÃO #3: DEADMAN é exceção - pode KILL imediatamente
        await killIdentity(identityId);

        return res.status(403).json({
          success: false,
          action: 'KILLED',
          error: 'Deadman timer expired - identity destroyed',
          reason: 'Deadman timer expired',
          timeSinceHeartbeat: Math.floor(timeSinceHeartbeat / 1000)
        });
      }
    }

    const config = paranoiaConfig[identity.paranoiaLevel];

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

    const features = await extractFeatures(identity, clientIP, userAgent);
    await trackEndpoint(identityId, 'check');
    const aiAnalysis = await analyzeWithAI(features);

    // ✅ CORREÇÃO #4: validateIdentity SEMPRE retorna objeto ou null
    // Objeto tem property isValidSignature: boolean
    const validatedIdentity = await validateIdentity(identityId, privateKey);

    // ✅ CORREÇÃO #5: NÃO retorna KILL se validatedIdentity é null
    // null significa "identity não encontrada ou expirada" - já tratado antes
    if (!validatedIdentity) {
      console.log(`[API] ❌ validateIdentity returned null (identity expired or deleted)`);
      return res.status(404).json({
        success: false,
        error: 'Identity not found or expired'
      });
    }

    const isValidSignature = validatedIdentity.isValidSignature;
    console.log(`[API] 🔑 isValidSignature: ${isValidSignature}`);

    // ========================================
    // VALIDAÇÃO BEM-SUCEDIDA
    // ========================================
    if (isValidSignature === true) {
      console.log(`[API] ✅ VALIDATION SUCCESSFUL - Valid cryptographic signature`);

      if (identity.paranoiaLevel === 'deadman') {
        const now = Date.now();
        identity.lastHeartbeat = now;
        identity.lastCheckIn = now;
        console.log(`[API] 💓 Heartbeat auto-updated`);
      }

      identity.attempts = 0;
      identity.attemptsAfterRegenerate = 0;
      await db.set(`identity:${identityId}`, identity);

      console.log(`[API] 🔄 Counters reset`);
      console.log(`[API] 🎯 Final Action: ALLOWED (validation successful)`);
      console.log(`[API] ========================================\n`);

      return res.json({
        success: true,
        action: 'ALLOWED',
        reason: 'Valid cryptographic signature',
        identity: {
          id: validatedIdentity.id,
          publicKey: validatedIdentity.publicKey,
          paranoiaLevel: validatedIdentity.paranoiaLevel,
          expiresAt: validatedIdentity.expiresAt,
          attempts: 0,
          totalAttempts: validatedIdentity.totalAttempts || 0,
          regenerationCount: validatedIdentity.regenerationCount || 0
        },
        aiAnalysis: aiAnalysis ? {
          threatScore: aiAnalysis.riskAnalysis.threatScore,
          confidence: aiAnalysis.riskAnalysis.confidence,
          topFactors: aiAnalysis.riskAnalysis.topFactors,
          pattern: aiAnalysis.threatPattern.pattern,
          aiWasIgnored: true
        } : null
      });
    }

    // ========================================
    // VALIDAÇÃO FALHOU
    // ========================================
    console.log(`[API] ❌ VALIDATION FAILED - Invalid private key`);

    // ✅ CORREÇÃO #6: Reload identity do Redis para garantir estado atual
    identity = await db.getIdentity(identityId);

    // ✅ CORREÇÃO #7: Se identity sumiu durante processamento, retorna 404
    // NÃO retorna KILL pois não foi o motor de decisão que matou
    if (!identity) {
      console.log(`[API] ⚠️ Identity disappeared during processing`);
      return res.status(404).json({
        success: false,
        error: 'Identity not found'
      });
    }

    // ✅ CORREÇÃO #8: Incrementa contadores ANTES de decisão
    identity.attempts = (identity.attempts || 0) + 1;
    identity.totalAttempts = (identity.totalAttempts || 0) + 1;
    identity.lastAttemptAt = Date.now();

    if (identity.regenerationCount > 0) {
      identity.attemptsAfterRegenerate = (identity.attemptsAfterRegenerate || 0) + 1;
    }

    await db.set(`identity:${identityId}`, identity);

    console.log(`[API] 📈 Updated AFTER failed validation:`);
    console.log(`[API]    ├─ Attempts: ${identity.attempts}`);
    console.log(`[API]    ├─ Total: ${identity.totalAttempts}`);
    console.log(`[API]    ├─ Regenerations: ${identity.regenerationCount}`);
    console.log(`[API]    └─ After regenerate: ${identity.attemptsAfterRegenerate}`);

    // ========================================
    // DECISÃO BASEADA EM REGRAS
    // ========================================
    let ruleBasedAction: DefensiveAction = DefensiveAction.ALLOW;
    let killReason = '';

    // 🔥 LÓGICA DE KILL - Após regeneração
    if (identity.regenerationCount > 0) {
      if (identity.attemptsAfterRegenerate >= 2) {
        ruleBasedAction = DefensiveAction.KILL;
        killReason = `2nd failed attempt after regeneration (${identity.attemptsAfterRegenerate}/2)`;
      }
    }

    // 🔥 LÓGICA DE LIE - 1ª tentativa após regeneração
    if (ruleBasedAction === DefensiveAction.ALLOW && 
        identity.regenerationCount > 0 && 
        identity.attemptsAfterRegenerate === 1) {
      ruleBasedAction = DefensiveAction.LIE;
    }

    // 🔥 LÓGICA DE REGENERATE - Usa > ao invés de >=
    if (ruleBasedAction === DefensiveAction.ALLOW && 
        identity.regenerationCount === 0 &&
        identity.attempts > config.regenerateThreshold) {
      ruleBasedAction = DefensiveAction.REGENERATE;
      console.log(`[API] 🔄 REGENERATE condition met:`);
      console.log(`[API]    ├─ attempts (${identity.attempts}) > threshold (${config.regenerateThreshold})`);
      console.log(`[API]    └─ regenerationCount: ${identity.regenerationCount}`);
    }

    // ========================================
    // COMBINA DECISÃO COM IA
    // ========================================
    const decisionContext: DecisionContext = {
      ruleBasedAction,
      aiRecommendation: aiAnalysis?.riskAnalysis.recommendedAction || null,
      validationSuccessful: false,
      threatScore: aiAnalysis?.riskAnalysis.threatScore || 0,
      confidence: aiAnalysis?.riskAnalysis.confidence || 'low',
      topFactors: aiAnalysis?.riskAnalysis.topFactors || [],
      identityId
    };

    const decisionResult = await combineDecisionsV3(decisionContext);
    const finalAction = decisionResult.action;

    console.log(`[API] 🎯 Rule-Based: ${ruleBasedAction}`);
    console.log(`[API] 🤖 AI Recommended: ${aiAnalysis?.riskAnalysis.recommendedAction || 'N/A'}`);
    console.log(`[API] ✅ Final Action: ${finalAction} (${decisionResult.aiContribution})`);
    console.log(`[API] 💯 Confidence: ${decisionResult.confidence.toFixed(2)}`);

    if (decisionResult.aiDisagreement) {
      console.log(`[API] ⚠️  AI DISAGREEMENT DETECTED:`);
      console.log(`[API]    ├─ AI wanted: ${decisionResult.aiDisagreement.aiWanted}`);
      console.log(`[API]    ├─ Rules chose: ${decisionResult.aiDisagreement.rulesChose}`);
      console.log(`[API]    └─ Reason: ${decisionResult.aiDisagreement.reason}`);
    }

    // ========================================
    // EXECUTA AÇÃO FINAL
    // ========================================

    // ✅ CORREÇÃO #9: KILL só acontece AQUI, após decisão
    if (finalAction === DefensiveAction.KILL) {
      console.log(`[API] 💀 KILL TRIGGERED BY DECISION ENGINE!`);
      console.log(`[API]    └─ Reason: ${killReason || decisionResult.reason}`);
      
      await killIdentity(identityId);

      return res.status(403).json({
        success: false,
        action: 'KILLED',
        reason: killReason || decisionResult.reason,
        message: '💀 Identity permanently destroyed',
        details: {
          attempts: identity.attempts,
          totalAttempts: identity.totalAttempts,
          maxAttempts: config.maxAttempts,
          regenerations: identity.regenerationCount,
          attemptsAfterRegenerate: identity.attemptsAfterRegenerate
        },
        aiAnalysis: aiAnalysis ? {
          threatScore: aiAnalysis.riskAnalysis.threatScore,
          confidence: aiAnalysis.riskAnalysis.confidence,
          topFactors: aiAnalysis.riskAnalysis.topFactors,
          pattern: aiAnalysis.threatPattern.pattern,
          aiContribution: decisionResult.aiContribution,
          aiDisagreement: decisionResult.aiDisagreement
        } : null
      });
    }

    if (finalAction === DefensiveAction.LIE) {
      console.log(`[API] 🎭 LIE TRIGGERED!`);

      return res.status(401).json({
        success: false,
        action: 'LIE',
        reason: decisionResult.reason,
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
        nextAction: 'KILL',
        aiAnalysis: aiAnalysis ? {
          threatScore: aiAnalysis.riskAnalysis.threatScore,
          confidence: aiAnalysis.riskAnalysis.confidence,
          topFactors: aiAnalysis.riskAnalysis.topFactors,
          aiContribution: decisionResult.aiContribution
        } : null
      });
    }

    if (finalAction === DefensiveAction.REGENERATE) {
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
        reason: decisionResult.reason,
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
        },
        aiAnalysis: aiAnalysis ? {
          threatScore: aiAnalysis.riskAnalysis.threatScore,
          confidence: aiAnalysis.riskAnalysis.confidence,
          aiContribution: decisionResult.aiContribution
        } : null
      });
    }

    // ALLOW (tentativa registrada)
    const remaining = config.maxAttempts - identity.attempts;

    return res.status(401).json({
      success: false,
      action: 'ALLOWED',
      error: 'Invalid identity or private key',
      attempts: identity.attempts,
      totalAttempts: identity.totalAttempts,
      maxAttempts: config.maxAttempts,
      remaining: remaining,
      message: `Failed attempt logged. ${remaining} attempts remaining.`,
      aiAnalysis: aiAnalysis ? {
        threatScore: aiAnalysis.riskAnalysis.threatScore,
        confidence: aiAnalysis.riskAnalysis.confidence,
        aiContribution: decisionResult.aiContribution
      } : null
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

    if (!validatedIdentity || !validatedIdentity.isValidSignature) {
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

    if (!validatedIdentity || !validatedIdentity.isValidSignature) {
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

    if (!validatedIdentity || !validatedIdentity.isValidSignature) {
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