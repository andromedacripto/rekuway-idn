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
 *
 * @param minMs Mínimo em ms (padrão: 200)
 * @param maxMs Máximo em ms (padrão: 1000)
 */
async function stealthDelay(minMs = 200, maxMs = 1000): Promise<void> {
  const delay = Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
  await new Promise((resolve) => setTimeout(resolve, delay));
}

/**
 * Envia a resposta stealth de falha.
 * Centraliza o envio para garantir consistência em TODOS os casos de erro.
 *
 * @param res       Objeto Response do Express
 * @param action    Ação interna (apenas para log — NUNCA vai para o cliente)
 * @param identityId ID da identidade (mascarado no log)
 */
async function sendStealthFailure(
  res: Response,
  action: DefensiveAction | 'INVALID_BODY' | 'NOT_FOUND' | 'DEADMAN_EXPIRED',
  identityId?: string
): Promise<void> {
  // Log interno seguro — registra o que realmente aconteceu
  safeLog(`[DEFENSE] ${action} triggered`, { identityId });

  // Delay antes de responder — mitiga timing attacks
  await stealthDelay();

  // Resposta pública: sempre idêntica, independente da ação
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

      // ✅ privateKey vai APENAS na resposta HTTP desta rota — NUNCA em logs
      res.json({
        success:  true,
        message:  '⚠️ SAVE YOUR PRIVATE KEY! It will never be shown again.',
        identity: {
          id:            result.identity.id,
          publicKey:     result.identity.publicKey,
          paranoiaLevel: result.identity.paranoiaLevel,
          expiresAt:     result.identity.expiresAt,
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
//  POST /identity/check  (STEALTH REFACTORED)
// ─────────────────────────────────────────────
router.post('/check', async (req: Request, res: Response) => {
  try {
    // ✅ SEGURO: privateKey extraída do body mas JAMAIS logada
    const { identityId, privateKey } = req.body;
    const clientIP  = req.ip || req.connection.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || '';

    // ── Validação de entrada ─────────────────────────────────
    if (!identityId || !privateKey) {
      // Sem delay aqui — falha antes mesmo de consultar o DB
      // Qualquer bot saberá que está faltando campo — não há segredo
      return res.status(400).json({ success: false, error: 'identityId and privateKey are required' });
    }

    // ── Busca identidade no DB ───────────────────────────────
    let identity = await db.getIdentity(identityId);

    // Identidade inexistente ou morta → stealth (pode ser KILL anterior)
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
        // ⚠️ STEALTH: não revela que foi DEADMAN_EXPIRED — apenas falha genérica
        await sendStealthFailure(res, 'DEADMAN_EXPIRED', identityId);
        return;
      }
    }

    const config = paranoiaConfig[identity.paranoiaLevel];

    // Inicializa contadores ausentes (compatibilidade retroativa)
    if (typeof identity.totalAttempts           === 'undefined') identity.totalAttempts           = identity.attempts;
    if (typeof identity.regenerationCount       === 'undefined') identity.regenerationCount       = 0;
    if (typeof identity.attemptsAfterRegenerate === 'undefined') identity.attemptsAfterRegenerate = 0;

    // ── Feature extraction + AI analysis ────────────────────
    // Mantém toda a lógica adaptativa existente intacta
    const features        = await extractFeatures(identity, clientIP, userAgent);
    await trackEndpoint(identityId, 'check');
    const aiAnalysis      = await analyzeWithAI(features);
    const railwayFeatures = convertToRailwayFeatures(features);
    const railwayAI       = await analyzeWithRailwayAI(railwayFeatures);
    const validatedIdentity = await validateIdentity(identityId, privateKey);

    if (!validatedIdentity) {
      await sendStealthFailure(res, DefensiveAction.ALLOW, identityId);
      return;
    }

    const isValidSignature = validatedIdentity.isValidSignature;

    // ── ALLOWED (assinatura válida) ──────────────────────────
    // Único caso que retorna dados reais — sem stealth necessário
    if (isValidSignature === true) {
      if (identity.paranoiaLevel === 'deadman') {
        const now = Date.now();
        identity.lastHeartbeat = now;
        identity.lastCheckIn   = now;
      }
      identity.attempts                = 0;
      identity.attemptsAfterRegenerate = 0;
      await db.set(`identity:${identityId}`, identity);

      // ✅ Sucesso: retorna dados reais sem delay
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

    // FIX: reler do DB após validateIdentity para garantir estado fresco
    identity = await db.getIdentity(identityId);
    if (!identity) {
      await sendStealthFailure(res, 'NOT_FOUND', identityId);
      return;
    }

    // FIX: incrementa ANTES de avaliar as regras
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
    // Lógica: destrói identidade
    // Resposta externa: genérica (stealth)
    if (finalAction === DefensiveAction.KILL) {
      await killIdentity(identityId);
      // ⚠️ STEALTH: não retorna { action: "KILLED" }
      await sendStealthFailure(res, DefensiveAction.KILL, identityId);
      return;
    }

    // ── LIE ──────────────────────────────────────────────────
    // Lógica: engana o atacante (retorna falha genérica idêntica)
    // NOTA: no código original, LIE retornava { action: 'ALLOWED' }
    // Com stealth: retorna STEALTH_FAILURE com delay — mesma aparência que ALLOW
    // O atacante não consegue distinguir LIE de ALLOW
    if (finalAction === DefensiveAction.LIE) {
      // ⚠️ STEALTH: não retorna { action: "LIE" } nem { action: "ALLOWED" }
      // O delay já está dentro de sendStealthFailure
      await sendStealthFailure(res, DefensiveAction.LIE, identityId);
      return;
    }

    // ── REGENERATE ───────────────────────────────────────────
    // Lógica: destrói identidade atual e cria nova
    // Resposta externa: genérica (stealth) — nova identidade NÃO é retornada
    // O sistema legítimo deve usar /identity/new para obter nova identidade
    if (finalAction === DefensiveAction.REGENERATE) {
      await killIdentity(identityId);
      const newIdentityResult = await createIdentity(identity.paranoiaLevel);

      if (!newIdentityResult) {
        safeError('[DEFENSE] REGENERATE failed to create new identity', { identityId });
        await stealthDelay();
        return res.status(randomFailureStatus()).json(STEALTH_FAILURE);
      }

      // Propaga contadores para a nova identidade
      const newIdentity                   = newIdentityResult.identity;
      newIdentity.totalAttempts           = identity.totalAttempts;
      newIdentity.regenerationCount       = (identity.regenerationCount || 0) + 1;
      newIdentity.attemptsAfterRegenerate = 0;
      await db.set(`identity:${newIdentity.id}`, newIdentity);

      // ⚠️ STEALTH: NÃO retorna { action: "REGENERATE" } nem a nova privateKey
      // Log interno registra o novo ID de forma segura
      safeLog('[DEFENSE] REGENERATE triggered — new identity created', {
        oldId: identityId,
        newId: newIdentity.id,
      });

      await sendStealthFailure(res, DefensiveAction.REGENERATE, identityId);
      return;
    }

    // ── ALLOW (falha simples) ─────────────────────────────────
    // Chave inválida mas sem threshold atingido — falha normal
    // ⚠️ STEALTH: não retorna { action: "ALLOWED" }
    await sendStealthFailure(res, DefensiveAction.ALLOW, identityId);

  } catch (error) {
    safeError('[API] ❌ Error in /check:', error);
    // Erro interno: sem delay (já custou tempo no processamento)
    // Status 500 para erros genuínos — não mascarar bugs como falha de auth
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

    // ✅ privateKey retornada na resposta — NUNCA em logs
    res.json({
      success:  true,
      identity: {
        id:            newIdentity.identity.id,
        publicKey:     newIdentity.identity.publicKey,
        paranoiaLevel: newIdentity.identity.paranoiaLevel,
        expiresAt:     newIdentity.identity.expiresAt,
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