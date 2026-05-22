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

// ── Rate Limiting por IP ──────────────────────────────────────
const rateLimitMap = new Map<string, { count: number; resetAt: number }>()
const RATE_LIMIT_MAX = 10
const RATE_LIMIT_WINDOW_MS = 60_000

function checkRateLimit(ip: string): boolean {
  const now = Date.now()
  const entry = rateLimitMap.get(ip)
  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS })
    return true
  }
  if (entry.count >= RATE_LIMIT_MAX) return false
  entry.count++
  return true
}


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
  success: true,
  status:  'ok',
  mode:    'stealth',
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
  return 200;
}

/**
 * Aplica um delay aleatório antes de responder com falha.
 *
 * Objetivos:
 *  1. Dificulta ataques de timing (timing oracle)
 *  2. Aumenta o custo de brute-force automatizado
 *  3. Mascara diferenças de tempo entre KILL, LIE e ALLOW
 */
async function stealthDelay(minMs = 80, maxMs = 120): Promise<void> {
  const delay = Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
  await new Promise((resolve) => setTimeout(resolve, delay));
}

/**
 * Envia a resposta stealth de falha.
 * Centraliza o envio para garantir consistência em TODOS os casos de erro.
 */
const STEALTH_RESPONSE = { success: true, status: 'ok', mode: 'stealth' } as const

async function sendStealthFailure(
  res: Response,
  action: DefensiveAction | 'INVALID_BODY' | 'NOT_FOUND' | 'DEADMAN_EXPIRED',
  identityId?: string
): Promise<void> {
  safeLog(`[DEFENSE] ${action} triggered`, { identityId });
  await stealthDelay();
  res.status(randomFailureStatus()).json(STEALTH_FAILURE);
}


// ── Geo + VPN Detection ──────────────────────────────────────
async function getGeoAndVPN(ip: string): Promise<{ country: string | null; city: string | null; isVPN: boolean; isDatacenter: boolean }> {
  try {
    if (!ip || ip === 'unknown' || ip.startsWith('192.168') || ip.startsWith('10.') || ip === '127.0.0.1') {
      return { country: 'Local', city: 'Local', isVPN: false, isDatacenter: false }
    }
    const r = await fetch(`http://ip-api.com/json/${ip}?fields=country,city,status,proxy,hosting`, { signal: AbortSignal.timeout(2500) })
    const d = await r.json() as any
    if (d.status !== 'success') return { country: null, city: null, isVPN: false, isDatacenter: false }
    return { country: d.country || null, city: d.city || null, isVPN: d.proxy === true, isDatacenter: d.hosting === true }
  } catch {
    return { country: null, city: null, isVPN: false, isDatacenter: false }
  }
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
          ...STEALTH_RESPONSE,
        });
      }

      const result = await createIdentity(paranoiaLevel);
      // ✅ Salvar userId na identidade para rastreamento
      if (req.apiKey?.userId) {
        result.identity.userId = req.apiKey.userId;
        await db.setIdentity(result.identity.id, result.identity);
      }

      // ✅ STEALTH: token opaco — parece um token comum
      // id + privateKey empacotados em base64url — nunca expostos separadamente
      // O atacante não consegue identificar que é um sistema de chaves RSA
      const credentialToken = encodeCredentialToken(
        result.identity.id,
        result.privateKey
      );

      // ✅ Callback IDENTITY_CREATED → dashboard
      const _userId = req.apiKey?.userId
      if (_userId) {
        const _dashUrl = process.env.DASHBOARD_URL || 'https://rekuway-dashboard.vercel.app'
        fetch(`${_dashUrl}/api/keys/event`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-internal-secret': process.env.INTERNAL_SECRET || '' },
          body: JSON.stringify({ userId: _userId, type: 'IDENTITY_CREATED', severity: 'LOW', description: `New identity created: ${result.identity.id} [${paranoiaLevel}]`, blocked: false }),
          signal: AbortSignal.timeout(3000)
        }).catch(() => {})
      }

      // ── External token opaco — não decodificável ──────────
      const externalToken = require('crypto').randomBytes(32).toString('hex')
      const ttlSeconds = Math.max(1, Math.floor((result.identity.expiresAt - Date.now()) / 1000))
      try {
        const { db: dbInst } = await import('../config/database')
        await dbInst.set(`ext:${externalToken}`, credentialToken, ttlSeconds)
      } catch (_) {}

      // Cold start masking
      const _newStart = Date.now()
      const _newElapsed = Date.now() - _newStart
      if (_newElapsed < 80) await new Promise(r => setTimeout(r, 80 - _newElapsed))
      await stealthDelay()
      res.status(200).json({
        success:   true,
        status:    'created',
        mode:      'stealth',
        token:     externalToken,
        expiresAt: result.identity.expiresAt,
      });

    } catch (error) {
      safeError('[API] Error creating identity:', error);
      res.status(200).json(STEALTH_RESPONSE);
    }
  }
);

// ─────────────────────────────────────────────
//  POST /identity/check  (STEALTH REFACTORED)
//  Timing protection — mascara diferença entre KILL, LIE, ALLOW
// ─────────────────────────────────────────────
router.post('/check', async (req: Request, res: Response) => {
    const _reqStart = Date.now()
    const clientIP = req.headers['x-forwarded-for']?.toString().split(',')[0] || req.socket.remoteAddress || 'unknown'
    if (!checkRateLimit(clientIP)) {
      return res.status(200).json(STEALTH_RESPONSE)
    }
  try {
    // ✅ SEGURO: resolve externalToken → credenciais reais
    const { token: extToken, identityId: rawId, privateKey: rawKey } = req.body;
    const clientIP  = req.ip || req.connection.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || '';

    let identityId = rawId
    let privateKey = rawKey

    // Resolver externalToken opaco se fornecido
    if (extToken && extToken.length === 64 && /^[0-9a-f]+$/.test(extToken)) {
      try {
        const { db: dbExt } = await import('../config/database')
        const realToken = await dbExt.get(`ext:${extToken}`)
        if (realToken) {
          const decoded = decodeCredentialToken(realToken as string)
          if (decoded) {
            identityId = decoded.identityId
            privateKey = decoded.privateKey
          }
        }
      } catch (_) {}
    }

    // Token rotation — invalida token antigo, gera novo
    let rotatedToken: string | null = null
    if (extToken && extToken.length === 64) {
      try {
        const { db: dbRot } = await import('../config/database')
        const existingReal = await dbRot.get(`ext:${extToken}`)
        if (existingReal) {
          rotatedToken = require('crypto').randomBytes(32).toString('hex')
          const ttlRem = 3600 // fallback TTL
          await dbRot.set(`ext:${rotatedToken}`, existingReal as string, ttlRem)
          await dbRot.set(`ext:${extToken}`, "", 1) // expire immediately
        }
      } catch (_) {}
    }

    if (!identityId || !privateKey) {
      // Anti-enumeration: executar delay igual ao fluxo real
      const _fakeStart = Date.now()
      await new Promise(r => setTimeout(r, 80 + Math.floor(Math.random() * 40)))
      return res.status(200).json(STEALTH_RESPONSE);
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
      { const _dashUrl = process.env.DASHBOARD_URL || 'https://rekuway-dashboard.vercel.app'; fetch(`${_dashUrl}/api/keys/event`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-internal-secret': process.env.INTERNAL_SECRET || '' }, body: JSON.stringify({ userId: identity?.userId, type: 'ATTACK_BLOCKED', severity: 'CRITICAL', description: `Deadman timer expired — identity killed: ${identityId}`, blocked: true, ipAddress: clientIP, userAgent, metadata: await getGeoAndVPN(clientIP) }), signal: AbortSignal.timeout(3000) }).catch(() => {}) }
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
      { const _dashUrl = process.env.DASHBOARD_URL || 'https://rekuway-dashboard.vercel.app'; fetch(`${_dashUrl}/api/keys/event`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-internal-secret': process.env.INTERNAL_SECRET || '' }, body: JSON.stringify({ userId: identity?.userId, type: 'ATTACK_BLOCKED', severity: 'HIGH', description: `Invalid private key attempt on identity: ${identityId}`, blocked: true, ipAddress: clientIP, userAgent, metadata: await getGeoAndVPN(clientIP) }), signal: AbortSignal.timeout(3000) }).catch(() => {}) }
      
    // ── Timing protection — normaliza tempo de resposta ─────
    const _elapsed = Date.now() - _reqStart
    const _target = 80 + Math.random() * 40
    if (_elapsed < _target) await new Promise(r => setTimeout(r, _target - _elapsed))
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
        body: JSON.stringify({ userId: identity.userId, type: 'ATTACK_BLOCKED', severity: 'CRITICAL', description: `Identity KILLED after attacks: ${identityId}`, blocked: true, ipAddress: clientIP, userAgent, metadata: await getGeoAndVPN(clientIP) }),
        signal: AbortSignal.timeout(3000)
      }).catch(() => {})
      
    // ── Timing protection — normaliza tempo de resposta ─────
    const _elapsed = Date.now() - _reqStart
    const _target = 120 + Math.random() * 30
    if (_elapsed < _target) await new Promise(r => setTimeout(r, _target - _elapsed))
    await sendStealthFailure(res, DefensiveAction.KILL, identityId);
      return;
    }

    // ── LIE ──────────────────────────────────────────────────
    if (finalAction === DefensiveAction.LIE) {
    // ── LIE INTELLIGENCE EVENT (interno — nunca vaza para o cliente) ──
    const lieEvent = {
      eventId: crypto.randomUUID(),
      timestamp: Date.now(),
      identityIdHash: require('crypto').createHash('sha256').update(identityId).digest('hex').slice(0, 16),
      action: 'LIE',
      lieStrategy: 'fake_success',
      actor: {
        ip: clientIP,
        forwardedFor: req.headers['x-forwarded-for'] || null,
        userAgent: userAgent || 'unknown',
        device: /mobile/i.test(userAgent) ? 'mobile' : /bot|curl|python|go-http/i.test(userAgent) ? 'bot' : 'desktop',
      },
      context: {
        attemptNumber: identity.attempts || 0,
        totalAttempts: identity.totalAttempts || 0,
        afterRegeneration: ((identity as any).regenerations || 0) > 0,
        regenerations: (identity as any).regenerations || 0,
      },
      risk: {
        level: (identity.attempts || 0) > 5 ? 'CRITICAL' : (identity.attempts || 0) > 3 ? 'HIGH' : 'MEDIUM',
        score: Math.min(100, ((identity.attempts || 0) * 15) + (((identity as any).regenerations || 0) * 20)),
      },
      fingerprint: require('crypto').createHash('sha256').update(clientIP + (userAgent || '')).digest('hex').slice(0, 32),
      decision: {
        reason: 'tentativa suspeita — sistema aplicou deception',
        nextAction: (identity.attempts || 0) >= 3 ? 'KILL' : 'MONITOR',
      }
    }
    // Salva internamente no Redis (nunca exposto via API)
    try {
      const { db } = await import('../config/database')
      await db.set(`lie_event:${lieEvent.eventId}`, lieEvent, 86400)
    } catch (_) {}

      { const _dashUrl = process.env.DASHBOARD_URL || 'https://rekuway-dashboard.vercel.app'; fetch(`${_dashUrl}/api/keys/event`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-internal-secret': process.env.INTERNAL_SECRET || '' }, body: JSON.stringify({ userId: identity?.userId, type: 'ATTACK_BLOCKED', severity: 'HIGH', description: `Attack deceived [LIE] on identity: ${identityId}`, blocked: true, ipAddress: clientIP, userAgent, metadata: await getGeoAndVPN(clientIP) }), signal: AbortSignal.timeout(3000) }).catch(() => {}) }
      
    // ── Timing protection — normaliza tempo de resposta ─────
    const _elapsed = Date.now() - _reqStart
    const _target = 120 + Math.random() * 30
    if (_elapsed < _target) await new Promise(r => setTimeout(r, _target - _elapsed))
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

      
    // ── Timing protection — normaliza tempo de resposta ─────
    const _elapsed = Date.now() - _reqStart
    const _target = 120 + Math.random() * 30
    if (_elapsed < _target) await new Promise(r => setTimeout(r, _target - _elapsed))
    await sendStealthFailure(res, DefensiveAction.REGENERATE, identityId);
      return;
    }

    // ── ALLOW (falha simples) ─────────────────────────────────
    { const _dashUrl = process.env.DASHBOARD_URL || 'https://rekuway-dashboard.vercel.app'; fetch(`${_dashUrl}/api/keys/event`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-internal-secret': process.env.INTERNAL_SECRET || '' }, body: JSON.stringify({ userId: identity?.userId, type: 'ATTACK_BLOCKED', severity: 'MEDIUM', description: `Failed attempt [ALLOW] on identity: ${identityId}`, blocked: true, ipAddress: clientIP, userAgent, metadata: await getGeoAndVPN(clientIP) }), signal: AbortSignal.timeout(3000) }).catch(() => {}) }
    
    // ── Timing protection — normaliza tempo de resposta ─────
    const _elapsed = Date.now() - _reqStart
    const _target = 120 + Math.random() * 30
    if (_elapsed < _target) await new Promise(r => setTimeout(r, _target - _elapsed))
    await sendStealthFailure(res, DefensiveAction.ALLOW, identityId);

  } catch (error) {
    safeError('[API] ❌ Error in /check:', error);
    res.status(200).json(STEALTH_RESPONSE);
  }
});

// ─────────────────────────────────────────────
//  POST /identity/heartbeat
// ─────────────────────────────────────────────
router.post('/heartbeat', async (req: Request, res: Response) => {
  try {
    const { identityId, privateKey } = req.body;

    if (!identityId || !privateKey) {
      return res.status(200).json(STEALTH_RESPONSE);
    }

    const identity = await db.getIdentity(identityId);

    if (!identity || !identity.isAlive) {
      return res.status(200).json(STEALTH_RESPONSE);
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
    const { id } = req.params;
    const identity = await db.getIdentity(id);
    if (!identity || !identity.isAlive) {
      return res.status(200).json(STEALTH_RESPONSE);
    }
    return res.status(200).json(STEALTH_RESPONSE);
  } catch (error) {
    return res.status(200).json(STEALTH_RESPONSE);
  }
});

export default router;