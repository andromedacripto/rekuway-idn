import { Router, Request, Response } from 'express';
import { createIdentity, validateIdentity, killIdentity, regenerateIdentity } from '../services/identityService';
import { defensiveResponse, detectThreatEvent } from '../services/defensiveService';
import { db } from '../config/database';
import { DefensiveAction } from '../models/Identity';
import paranoiaConfig from '../config/paranoia.json';

const router = Router();

/**
 * POST /identity/new
 * CRIA UMA NOVA IDENTIDADE TEMPORÁRIA
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
 * 
 * 🔥 SISTEMA DE DEFESA HÍBRIDA INTELIGENTE - CORRIGIDO
 * 
 * CAMADAS DE DEFESA:
 * 1. ALLOW → Registra tentativa
 * 2. REGENERATE → Cria nova identidade
 * 3. LIE → Retorna dados falsos (1ª falha após regenerar)
 * 4. KILL → Destruição permanente (2ª falha após regenerar)
 * 
 * EXEMPLO HIGH (maxAttempts: 3, regenerateThreshold: 2):
 * - Tentativa 1 ❌ → ALLOW (attempts: 1, total: 1)
 * - Tentativa 2 ❌ → REGENERATE (nova identidade, regenerations: 1)
 * - Tentativa 3 ❌ → LIE! 🎭 (attemptsAfterRegenerate: 1)
 * - Tentativa 4 ❌ → KILL! 💀 (attemptsAfterRegenerate: 2)
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

    // ========================================
    // 1. BUSCA IDENTIDADE
    // ========================================
    let identity = await db.getIdentity(identityId);

    if (!identity || !identity.isAlive) {
      console.log(`[API] ❌ Identity not found or dead`);
      return res.status(404).json({
        success: false,
        error: 'Invalid identity or private key'
      });
    }

    const config = paranoiaConfig[identity.paranoiaLevel];
    
    // Inicializa contadores se não existirem
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

    // ========================================
    // 2. VALIDA CHAVE PRIVADA
    // ========================================
    const validatedIdentity = await validateIdentity(identityId, privateKey);

    // ========================================
    // ✅ VALIDAÇÃO BEM-SUCEDIDA
    // ========================================
    if (validatedIdentity) {
      console.log(`[API] ✅ Validation SUCCESSFUL`);

      // Reseta attempts e attemptsAfterRegenerate
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

    // ========================================
    // ❌ VALIDAÇÃO FALHOU (chave errada)
    // ========================================
    console.log(`[API] ❌ Validation FAILED - Invalid private key`);

    // Busca identidade atualizada (validateIdentity já incrementou attempts)
    identity = await db.getIdentity(identityId);

    if (!identity) {
      return res.status(404).json({
        success: false,
        error: 'Invalid identity or private key'
      });
    }

    // 🔥 INCREMENTA CONTADORES GLOBAIS
    identity.totalAttempts = (identity.totalAttempts || 0) + 1;
    
    // 🔥 INCREMENTA attemptsAfterRegenerate SOMENTE SE JÁ REGENEROU
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
    // 💀 DECISÃO 1: KILL (prioridade máxima)
    // Lógica:
    // - SE JÁ REGENEROU: usa attemptsAfterRegenerate >= 2
    // - SE NÃO REGENEROU: usa totalAttempts >= maxAttempts
    // ========================================
    let shouldKill = false;
    let killReason = '';

    if (identity.regenerationCount > 0) {
      // Após regeneração: mata na 2ª tentativa
      shouldKill = identity.attemptsAfterRegenerate >= 2;
      killReason = `2nd failed attempt after regeneration (${identity.attemptsAfterRegenerate}/2)`;
    } else {
      // Antes de regenerar: mata quando atinge maxAttempts
      shouldKill = identity.totalAttempts >= config.maxAttempts;
      killReason = `Maximum total attempts exceeded (${identity.totalAttempts}/${config.maxAttempts})`;
    }

    if (shouldKill) {
      console.log(`[API] 💀 KILL TRIGGERED!`);
      console.log(`[API]    ├─ Reason: ${killReason}`);
      console.log(`[API]    ├─ Total: ${identity.totalAttempts}/${config.maxAttempts}`);
      console.log(`[API]    ├─ Regenerations: ${identity.regenerationCount}`);
      console.log(`[API]    ├─ After regenerate: ${identity.attemptsAfterRegenerate}`);
      console.log(`[API]    └─ Action: 💀 PERMANENT DESTRUCTION`);
      
      await killIdentity(identityId);
      
      return res.status(403).json({
        success: false,
        action: 'KILLED',
        reason: killReason,
        message: '💀 Identity permanently destroyed',
        details: {
          totalAttempts: identity.totalAttempts,
          maxAttempts: config.maxAttempts,
          regenerations: identity.regenerationCount,
          attemptsAfterRegenerate: identity.attemptsAfterRegenerate
        }
      });
    }

    // ========================================
    // 🎭 DECISÃO 2: LIE (defesa híbrida)
    // Condição: 1ª tentativa após regeneração
    // ========================================
    if (identity.regenerationCount > 0 && identity.attemptsAfterRegenerate === 1) {
      console.log(`[API] 🎭 LIE TRIGGERED!`);
      console.log(`[API]    ├─ Reason: 1st attempt after regeneration`);
      console.log(`[API]    ├─ Regenerations: ${identity.regenerationCount}`);
      console.log(`[API]    ├─ After regenerate: ${identity.attemptsAfterRegenerate}/2`);
      console.log(`[API]    ├─ Action: 🎭 DECEIVING ATTACKER`);
      console.log(`[API]    └─ Warning: Next failure = KILL`);
      
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

    // ========================================
    // 🔄 DECISÃO 3: REGENERATE
    // ========================================
    if (identity.attempts >= config.regenerateThreshold) {
      console.log(`[API] 🔄 REGENERATE TRIGGERED!`);
      console.log(`[API]    ├─ Reason: Threshold reached`);
      console.log(`[API]    ├─ Attempts: ${identity.attempts}/${config.regenerateThreshold}`);
      console.log(`[API]    ├─ Total: ${identity.totalAttempts}/${config.maxAttempts}`);
      console.log(`[API]    └─ Action: 🔄 CREATING NEW IDENTITY`);
      
      await killIdentity(identityId);
      
      const newIdentityResult = await createIdentity(identity.paranoiaLevel);
      
      if (!newIdentityResult) {
        console.log(`[API] ❌ Failed to create new identity`);
        return res.status(500).json({
          success: false,
          error: 'Failed to regenerate identity'
        });
      }

      // Transfere contadores
      const newIdentity = newIdentityResult.identity;
      newIdentity.totalAttempts = identity.totalAttempts;
      newIdentity.regenerationCount = (identity.regenerationCount || 0) + 1;
      newIdentity.attemptsAfterRegenerate = 0; // 🔥 RESETA
      await db.set(`identity:${newIdentity.id}`, newIdentity);

      console.log(`[API] ✅ New identity created: ${newIdentity.id}`);
      console.log(`[API]    ├─ Total preserved: ${newIdentity.totalAttempts}`);
      console.log(`[API]    ├─ Regenerations: ${newIdentity.regenerationCount}`);
      console.log(`[API]    └─ Next layers: LIE → KILL`);

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

    // ========================================
    // ⚠️ DECISÃO 4: ALLOW (registra tentativa)
    // ========================================
    const remaining = config.maxAttempts - identity.totalAttempts;
    
    console.log(`[API] ⚠️ ALLOW - Failed attempt logged`);
    console.log(`[API]    ├─ Attempts: ${identity.attempts}`);
    console.log(`[API]    ├─ Total: ${identity.totalAttempts}/${config.maxAttempts}`);
    console.log(`[API]    └─ Remaining: ${remaining}`);
    
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
      error: 'Failed to check identity'
    });
  }
});

/**
 * POST /identity/regenerate
 * REGENERA MANUALMENTE
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
 * PANIC BUTTON
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
 * Verifica status sem autenticação
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
      remaining: config.maxAttempts - (identity.totalAttempts || identity.attempts)
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