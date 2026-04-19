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
//  TOKEN ENCODING — Stealth Credential Layer
//  Empacota id + privateKey num token opaco.
//  Para o atacante parece um token comum.
//  Para o cliente legítimo é decodificável.
// ─────────────────────────────────────────────

/**
 * Codifica id + privateKey num token base64url opaco.
 *
 * Formato interno (nunca documentado publicamente):
 *   base64url({ i: identityId, k: privateKey, t: timestamp, v: 1 })
 *
 * Para o atacante parece um token JWT comum.
 * Para o cliente legítimo é decodificável com qualquer base64 decoder.
 *
 * NUNCA logar o resultado desta função.
 */
function encodeCredentialToken(identityId: string, privateKey: string): string {
  const payload = JSON.stringify({
    i: identityId,
    k: privateKey,
    t: Date.now(),
    v: 1,
  });
  return Buffer.from(payload).toString('base64url');
}

/**
 * Decodifica o token de credencial.
 * Exportada para uso nos clientes legítimos (GLPI, Zabbix, Mautic, etc).
 * Retorna null se o token for inválido.
 *
 * Uso no cliente:
 *   const { identityId, privateKey } = decodeCredentialToken(token);
 */
export function decodeCredentialToken(token: string): {
  identityId: string;
  privateKey: string;
} | null {
  try {
    const decoded = JSON.parse(Buffer.from(token, 'base64url').toString('utf8'));
    if (!decoded.i || !decoded.k) return null;
    return { identityId: decoded.i, privateKey: decoded.k };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────
//  STEALTH LAYER
//  Camada de ofuscação de respostas HTTP.
//  Nenhuma lógica interna deve vazar para o cliente.
// ─────────────────────────────────────────────

/**
 * Resposta canônica de falha — idêntica para QUALQUER erro de autenticação.
 * KILL, LIE, REGENERATE e falha simples retornam exatamente a mesma coisa.
 * O atacante não consegue distinguir o que aconteceu internamente.
 */
const STEALTH_FAILURE = {
  success: false,
  error:   'Invalid identity or private key',
} as const;

/**
 * Status HTTP permitidos para respostas de falha.
 * Randomizados para dificultar fingerprinting do sistema.
 */
const FAILURE_STATUS_POOL = [401, 403, 404] as const;

/**
 * Seleciona um status HTTP aleatório do pool de falha.
 * Impede que atacantes identifiquem o tipo de falha pelo status code.
 */
function randomFailureStatus(): number {
  return FAILURE_STATUS_POOL[Math.floor(Math.random() * FAILURE_STATUS_POOL.length)];
}

/**
 * Aplica um delay aleatório antes de responder com falha.
 *
 * Objetivos:
 *  1. Dificulta ataques de timing (timing oracle)
 *  2. Aumenta o custo de brute-force automatizado
 *  3. Mascara diferenças de tempo entre KILL, LIE e ALLOW
 */
async function stealthDelay(minMs = 200, maxMs = 1000): Promise<void> {
  const delay = Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
  await new Promise((resolve) => setTimeout(resolve, delay));
}

/**
 * Envia a resposta stealth de falha.
 * Centraliza o envio para garantir consistência em TODOS os casos de erro.
 */
async function sendStealthFailure(
  res: Response,
  action: DefensiveAction | 'INVALID_BODY' | 'NOT_FOUND' | 'DEADMAN_EXPIRED',
  identityId?: string
): Promise<void> {
  safeLog(`[DEFENSE] ${action} triggered`, { identityId });
  await stealthDelay();
  res.status(randomFailureStatus()).json(STEALTH_FAILURE);
}

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
      // ✅ Salvar userId na identidade para rastreamento
      if (req.apiKey?.userId) {
        const { db } = await import('../config/database');
        const stored = await db.getIdentity(result.identity.id);
        if (stored) {
          stored.userId = req.apiKey.userId;
          await db.set(`identity:${result.identity.id}`, stored);
        }
      }

      // ✅ STEALTH: token opaco — parece um token comum
      // id + privateKey empacotados em base64url — nunca expostos separadamente
      // O atacante não consegue identificar que é um sistema de chaves RSA
      const credentialToken = encodeCredentialToken(
        result.identity.id,
        result.privateKey
      );

      res.json({
        success: true,
        token:   credentialToken,   // contém id + privateKey codificados
        exp:     result.identity.expiresAt,
        lvl:     result.identity.paranoiaLevel,
      });

    } catch (error) {
      safeError('[API] Error creating identity:', error);
      res.status(500).json({ success: false, error: 'Failed to create identity' });
    }
  }
);

// ─────────────────────────────────────────────
//  POST /identity/check  (STEALTH REFACTORED)
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
      await sendStealthFailure(res, 'NOT_FOUND', identityId);
      return;
    }

    // ── Verificação DEADMAN timer ────────────────────────────
    if (identity.paranoiaLevel === 'deadman') {
      const config         = paranoiaConfig.deadman;
      const deadmanTimerMs = (config.deadmanTimer || 60) * 1000;
      const lastHeartbeat  = identity.lastHeartbeat || identity.lastCheckIn || identity.createdAt;
      const timeSince      = Date.now() - lastHeartbeat;

      if (timeSince > deadmanTimerMs) {
        await killIdentity(identityId);
        await sendStealthFailure(res, 'DEADMAN_EXPIRED', identityId);
        return;
      }
    }

    const config = paranoiaConfig[identity.paranoiaLevel];

    if (typeof identity.totalAttempts           === 'undefined') identity.totalAttempts           = identity.attempts;
    if (typeof identity.regenerationCount       === 'undefined') identity.regenerationCount       = 0;
    if (typeof identity.attemptsAfterRegenerate === 'undefined') identity.attemptsAfterRegenerate = 0;

    // ── Feature extraction + AI analysis ────────────────────
    const features          = await extractFeatures(identity, clientIP, userAgent);
    await trackEndpoint(identityId, 'check');
    const aiAnalysis        = await analyzeWithAI(features);
    const railwayFeatures   = convertToRailwayFeatures(features);
    const railwayAI         = await analyzeWithRailwayAI(railwayFeatures);
    const validatedIdentity = await validateIdentity(identityId, privateKey);

    if (!validatedIdentity) {
      await sendStealthFailure(res, DefensiveAction.ALLOW, identityId);
      return;
    }

    const isValidSignature = validatedIdentity.isValidSignature;

    // ── ALLOWED (assinatura válida) ──────────────────────────
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
        success:  true,
        action:   'ALLOWED',
        identity: {
          id:            validatedIdentity.id,
          publicKey:     validatedIdentity.publicKey,
          paranoiaLevel: validatedIdentity.paranoiaLevel,
          expiresAt:     validatedIdentity.expiresAt,
        },
      });
    }

    // ── Falha de validação → avalia ação defensiva ───────────
    identity = await db.getIdentity(identityId);
    if (!identity) {
      await sendStealthFailure(res, 'NOT_FOUND', identityId);
      return;
    }

    identity.attempts               = (identity.attempts || 0) + 1;
    identity.totalAttempts          = (identity.totalAttempts || 0) + 1;
    identity.lastAttemptAt          = Date.now();
    if (identity.regenerationCount > 0) {
      identity.attemptsAfterRegenerate = (identity.attemptsAfterRegenerate || 0) + 1;
    }
    await db.set(`identity:${identityId}`, identity);

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
      const dashUrl = process.env.DASHBOARD_URL || 'https://rekuway-dashboard.vercel.app'
      fetch(`${dashUrl}/api/keys/event`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-internal-secret': process.env.INTERNAL_SECRET || '' },
        body: JSON.stringify({ userId: identity.userId, type: 'ATTACK_BLOCKED', severity: 'CRITICAL', description: `Identity KILLED after attacks: ${identityId}`, blocked: true, ipAddress: clientIP, userAgent }),
        signal: AbortSignal.timeout(3000)
      }).catch(() => {})
      await sendStealthFailure(res, DefensiveAction.KILL, identityId);
      return;
    }

    // ── LIE ──────────────────────────────────────────────────
    if (finalAction === DefensiveAction.LIE) {
      await sendStealthFailure(res, DefensiveAction.LIE, identityId);
      return;
    }

    // ── REGENERATE ───────────────────────────────────────────
    if (finalAction === DefensiveAction.REGENERATE) {
      await killIdentity(identityId);
      const newIdentityResult = await createIdentity(identity.paranoiaLevel);

      if (!newIdentityResult) {
        safeError('[DEFENSE] REGENERATE failed to create new identity', { identityId });
        await stealthDelay();
        return res.status(randomFailureStatus()).json(STEALTH_FAILURE);
      }

      const newIdentity                   = newIdentityResult.identity;
      newIdentity.totalAttempts           = identity.totalAttempts;
      newIdentity.regenerationCount       = (identity.regenerationCount || 0) + 1;
      newIdentity.attemptsAfterRegenerate = 0;
      newIdentity.userId                  = identity.userId;
      await db.set(`identity:${newIdentity.id}`, newIdentity);

      safeLog('[DEFENSE] REGENERATE triggered — new identity created', {
        oldId: identityId,
        newId: newIdentity.id,
      });

      // ✅ Callback para dashboard registrar rotação
      const dashUrl = process.env.DASHBOARD_URL || 'https://rekuway-dashboard.vercel.app'
      fetch(`${dashUrl}/api/keys/event`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-internal-secret': process.env.INTERNAL_SECRET || '' },
        body: JSON.stringify({ userId: identity.userId || req.apiKey?.userId, type: 'IDENTITY_ROTATION', severity: 'MEDIUM', description: `Identity rotated: ${identityId} → ${newIdentity.id}`, blocked: false }),
        signal: AbortSignal.timeout(3000)
      }).catch(() => {})

      await sendStealthFailure(res, DefensiveAction.REGENERATE, identityId);
      return;
    }

    // ── ALLOW (falha simples) ─────────────────────────────────
    await sendStealthFailure(res, DefensiveAction.ALLOW, identityId);

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
      success:  true,
      identity: {
        id:               identity.id,
        paranoiaLevel:    identity.paranoiaLevel,
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

    // ✅ STEALTH: token opaco — mesmo padrão do /identity/new
    const credentialToken = encodeCredentialToken(
      newIdentity.identity.id,
      newIdentity.privateKey
    );

    res.json({
      success: true,
      token:   credentialToken,
      exp:     newIdentity.identity.expiresAt,
      lvl:     newIdentity.identity.paranoiaLevel,
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
      exists:        true,
      paranoiaLevel: identity.paranoiaLevel,
      expiresAt:     identity.expiresAt,
    });

  } catch (error) {
    safeError('[API] Error checking status:', error);
    res.status(500).json({ success: false, error: 'Failed to check status' });
  }
});

export default router;