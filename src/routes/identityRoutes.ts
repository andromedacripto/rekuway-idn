import { Router, Request, Response } from 'express';
import { createIdentity, validateIdentity, killIdentity, regenerateIdentity } from '../services/identityService';
import { defensiveResponse, detectThreatEvent } from '../services/defensiveService';
import { db } from '../config/database';
import { DefensiveAction } from '../models/Identity';
import paranoiaConfig from '../config/paranoia.json';

const router = Router();

/**
 * POST /identity/new
 * 
 * CRIA UMA NOVA IDENTIDADE TEMPORÁRIA
 * Esta é a ÚNICA vez que a chave privada é exposta!
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
 * VALIDA UMA IDENTIDADE COM SISTEMA DEFENSIVO COMPLETO
 * Implementa as 4 ações: ALLOW, LIE, REGENERATE, KILL
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

    console.log(`[API] ========================================`);
    console.log(`[API] Check from IP: ${clientIP} | Identity: ${identityId}`);

    // 1. BUSCA IDENTIDADE
    let identity = await db.getIdentity(identityId);

    if (!identity || !identity.isAlive) {
      console.log(`[API] ❌ Identity not found or dead`);
      return res.status(404).json({
        success: false,
        error: 'Invalid identity or private key'
      });
    }

    const config = paranoiaConfig[identity.paranoiaLevel];
    console.log(`[API] Level: ${identity.paranoiaLevel} | Attempts: ${identity.attempts}/${config.maxAttempts} | Regenerate: ${config.regenerateThreshold}`);

    // 2. VALIDA CHAVE PRIVADA
    const validatedIdentity = await validateIdentity(identityId, privateKey);

    // ========================================
    // VALIDAÇÃO FALHOU (chave errada)
    // ========================================
    if (!validatedIdentity) {
      console.log(`[API] ❌ Validation FAILED`);

      // Busca identidade atualizada (attempts incrementado)
      identity = await db.getIdentity(identityId);

      if (!identity) {
        return res.status(404).json({
          success: false,
          error: 'Invalid identity or private key'
        });
      }

      console.log(`[API] Updated attempts: ${identity.attempts}/${config.maxAttempts}`);

      // ⚡ DECISÃO 1: KILL - Atingiu maxAttempts
      if (identity.attempts >= config.maxAttempts) {
        console.log(`[API] 💀 KILL - Max attempts reached (${identity.attempts}/${config.maxAttempts})`);
        await killIdentity(identityId);
        
        return res.status(403).json({
          success: false,
          action: 'KILLED',
          reason: `Too many failed attempts (${identity.attempts}/${config.maxAttempts})`,
          message: '💀 Identity has been destroyed'
        });
      }

      // ⚡ DECISÃO 2: REGENERATE - Atingiu regenerateThreshold
      if (config.regenerateThreshold && identity.attempts >= config.regenerateThreshold) {
        console.log(`[API] 🔄 REGENERATE - Threshold reached (${identity.attempts}/${config.regenerateThreshold})`);
        
        const newIdentity = await regenerateIdentity(identityId);
        
        if (!newIdentity) {
          return res.status(500).json({
            success: false,
            error: 'Failed to regenerate identity'
          });
        }

        return res.json({
          success: true,
          action: 'REGENERATE',
          reason: `Identity regenerated after ${identity.attempts} suspicious attempts`,
          message: '🔄 Identity regenerated. Old identity destroyed.',
          newIdentity: {
            id: newIdentity.identity.id,
            publicKey: newIdentity.identity.publicKey,
            privateKey: newIdentity.privateKey,
            paranoiaLevel: newIdentity.identity.paranoiaLevel,
            expiresAt: newIdentity.identity.expiresAt
          }
        });
      }

      // ⚡ DECISÃO 3: ALLOW (com warning)
      console.log(`[API] ⚠️ ALLOW - Failed attempt logged (${identity.attempts}/${config.maxAttempts})`);
      
      return res.status(401).json({
        success: false,
        action: 'ALLOWED',
        error: 'Invalid identity or private key',
        attempts: identity.attempts,
        remaining: config.maxAttempts - identity.attempts,
        message: `Attempt ${identity.attempts}/${config.maxAttempts}. ${config.maxAttempts - identity.attempts} attempts remaining.`
      });
    }

    // ========================================
    // VALIDAÇÃO BEM-SUCEDIDA
    // ========================================
    console.log(`[API] ✅ Validation SUCCESSFUL`);

    // Detecta tipo de ameaça
    const timeSinceLastAttempt = Date.now() - validatedIdentity.lastAttemptAt;
    const threatEvent = detectThreatEvent(validatedIdentity, clientIP, timeSinceLastAttempt);

    console.log(`[API] Threat: ${threatEvent}`);

    // Chama sistema defensivo
    const defensiveResult = await defensiveResponse(validatedIdentity, threatEvent, clientIP);

    console.log(`[API] Defensive action: ${defensiveResult.action}`);
    console.log(`[API] ========================================`);

    // Retorna baseado na ação defensiva
    switch (defensiveResult.action) {
      case DefensiveAction.KILL:
        return res.status(403).json({
          success: false,
          action: 'KILLED',
          reason: defensiveResult.reason,
          message: '💀 Identity destroyed due to suspicious activity'
        });

      case DefensiveAction.REGENERATE:
        return res.json({
          success: true,
          action: 'REGENERATE',
          reason: defensiveResult.reason,
          message: '🔄 Identity regenerated due to suspicious activity',
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
            id: defensiveResult.identity.id,
            publicKey: defensiveResult.identity.publicKey,
            paranoiaLevel: defensiveResult.identity.paranoiaLevel,
            expiresAt: defensiveResult.identity.expiresAt,
            attempts: defensiveResult.identity.attempts
          }
        });
    }

  } catch (error) {
    console.error('[API] Error checking identity:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to check identity'
    });
  }
});

/**
 * POST /identity/regenerate
 * 
 * REGENERA UMA IDENTIDADE MANUALMENTE
 * Mata a antiga e cria nova com mesmo nível de paranoia
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
      message: '🔄 Identity regenerated successfully',
      identity: newIdentity.identity,
      privateKey: newIdentity.privateKey
    });

  } catch (error) {
    console.error('[API] Error regenerating identity:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to regenerate identity'
    });
  }
});

/**
 * POST /identity/kill
 * 
 * PANIC BUTTON - Destrói identidade imediatamente
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
      message: '💀 Identity destroyed successfully'
    });

  } catch (error) {
    console.error('[API] Error killing identity:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to destroy identity'
    });
  }
});

/**
 * GET /identity/status/:id
 * 
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
      maxAttempts: config.maxAttempts,
      remaining: config.maxAttempts - identity.attempts
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