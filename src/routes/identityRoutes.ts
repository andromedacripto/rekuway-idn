import { Router, Request, Response } from 'express';
import { createIdentity, validateIdentity, killIdentity } from '../services/identityService';
import { defensiveResponse, detectThreatEvent } from '../services/defensiveService';
import { db } from '../config/database';
import { DefensiveAction } from '../models/Identity';
import { requireApiKey, checkIdentityCreationLimit } from '../middleware/authMiddleware';

const router = Router();

// TODOS os endpoints agora exigem API key
router.use(requireApiKey);

/**
 * POST /identity/new
 * 
 * CRIA UMA NOVA IDENTIDADE TEMPORÁRIA
 * 
 * Requer: API key válida
 * 
 * Body:
 * {
 *   "paranoiaLevel": "low" | "medium" | "high" | "deadman"
 * }
 * 
 * Response:
 * {
 *   "success": true,
 *   "identity": { id, publicKey, expiresAt, ... },
 *   "privateKey": "..." // ⚠️ SALVE ISSO! Nunca será mostrado novamente
 * }
 */
router.post('/new', checkIdentityCreationLimit, async (req: Request, res: Response) => {
  try {
    const { paranoiaLevel = 'medium' } = req.body;

    // Valida nível de paranoia
    if (!['low', 'medium', 'high', 'deadman'].includes(paranoiaLevel)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid paranoia level. Use: low, medium, high, or deadman'
      });
    }

    // Cria identidade
    const { identity, privateKey } = await createIdentity(paranoiaLevel);

    // Remove dados sensíveis da resposta
    const safeIdentity = {
      id: identity.id,
      publicKey: identity.publicKey,
      paranoiaLevel: identity.paranoiaLevel,
      createdAt: identity.createdAt,
      expiresAt: identity.expiresAt,
      isAlive: identity.isAlive
    };

    res.status(201).json({
      success: true,
      message: '⚠️ SAVE YOUR PRIVATE KEY! It will never be shown again.',
      identity: safeIdentity,
      privateKey: privateKey // Única vez que a chave privada é exposta
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
 * VALIDA IDENTIDADE E EXECUTA LÓGICA DEFENSIVA
 * 
 * Body:
 * {
 *   "identityId": "...",
 *   "privateKey": "..."
 * }
 * 
 * Response pode variar baseado na ação defensiva:
 * - ALLOW: retorna identidade válida
 * - LIE: retorna metadados falsos
 * - REGENERATE: retorna nova identidade
 * - KILL: informa que identidade foi destruída
 */
router.post('/check', async (req: Request, res: Response) => {
  try {
    const { identityId, privateKey } = req.body;

    if (!identityId || !privateKey) {
      return res.status(400).json({
        success: false,
        error: 'identityId and privateKey are required'
      });
    }

    // Pega IP do cliente
    const clientIP = (req as any).clientIP || req.ip || 'unknown';

    // Rastreia tentativa por IP
    const ipAttempts = await db.trackIP(clientIP);

    // Valida identidade
    const identity = await validateIdentity(identityId, privateKey);

    if (!identity) {
      return res.status(401).json({
        success: false,
        error: 'Invalid identity or private key',
        attempts: ipAttempts
      });
    }

    // Calcula tempo desde última tentativa
    const now = Date.now();
    const timeSinceLastAttempt = now - identity.lastAttemptAt;

    // Detecta tipo de ameaça
    const threatEvent = detectThreatEvent(identity, clientIP, timeSinceLastAttempt);

    // Executa análise defensiva
    const response = await defensiveResponse(identity, threatEvent, clientIP);

    // Responde baseado na ação defensiva decidida
    switch (response.action) {
      case DefensiveAction.KILL:
        return res.status(410).json({
          success: false,
          action: 'KILLED',
          reason: response.reason,
          message: '💀 Identity has been destroyed'
        });

      case DefensiveAction.REGENERATE:
        return res.status(200).json({
          success: true,
          action: 'REGENERATED',
          reason: response.reason,
          message: '🔄 Identity regenerated due to suspicious activity',
          newIdentity: response.newIdentity ? {
            id: response.newIdentity.identity.id,
            publicKey: response.newIdentity.identity.publicKey,
            privateKey: response.newIdentity.privateKey,
            expiresAt: response.newIdentity.identity.expiresAt
          } : null
        });

      case DefensiveAction.LIE:
        return res.status(200).json({
          success: true,
          action: 'LYING',
          reason: response.reason,
          message: '🎭 Returning fake metadata',
          identity: {
            id: identity.id,
            metadata: response.fakeData
          }
        });

      case DefensiveAction.ALLOW:
        return res.status(200).json({
          success: true,
          action: 'ALLOWED',
          reason: response.reason,
          identity: {
            id: identity.id,
            publicKey: identity.publicKey,
            expiresAt: identity.expiresAt,
            attempts: identity.attempts
          }
        });

      default:
        return res.status(500).json({
          success: false,
          error: 'Unknown defensive action'
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
 * POST /identity/kill
 * 
 * DESTRÓI UMA IDENTIDADE IMEDIATAMENTE
 * Usado como "panic button" ou em situações de coerção
 * 
 * Body:
 * {
 *   "identityId": "...",
 *   "privateKey": "..."
 * }
 * 
 * Response:
 * {
 *   "success": true,
 *   "message": "Identity destroyed"
 * }
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

    // Valida que o usuário possui a chave privada
    const identity = await validateIdentity(identityId, privateKey);

    if (!identity) {
      return res.status(401).json({
        success: false,
        error: 'Invalid identity or private key'
      });
    }

    // Mata identidade
    const killed = await killIdentity(identityId);

    if (killed) {
      res.status(200).json({
        success: true,
        message: '💀 Identity destroyed successfully'
      });
    } else {
      res.status(500).json({
        success: false,
        error: 'Failed to destroy identity'
      });
    }

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
 * VERIFICA STATUS DE UMA IDENTIDADE (sem autenticação)
 * Útil para verificar se uma identidade ainda existe
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

    res.json({
      exists: true,
      expiresAt: identity.expiresAt,
      paranoiaLevel: identity.paranoiaLevel
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