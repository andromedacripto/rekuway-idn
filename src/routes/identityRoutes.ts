import crypto from 'crypto';
import { Router, Request, Response } from 'express';
import {
  createIdentity,
  validateIdentity,
  killIdentity,
  regenerateIdentity,
} from '../services/identityService';
import { updateHeartbeat } from '../services/heartbeat';
import { db } from '../config/database';
import { DefensiveAction } from '../models/Identity';
import { requireApiKey, checkIdentityCreationLimit } from '../middleware/auth';
import { safeLog, safeError } from '../utils/sanitize';
import paranoiaConfig from '../config/paranoia.json';
import { extractFeatures, trackEndpoint } from '../services/featureExtraction';
import { analyzeWithAI } from '../services/aiClient';
import { analyzeWithRailwayAI, convertToRailwayFeatures } from '../services/railwayAiClient';
import { combineDecisionsV3, computeRuleBasedAction } from '../services/decisionEngine';
import { getClientIp } from '../utils/clientIp';
import { sealToken, openToken } from '../utils/tokenVault';
import { isBlocked, isOverLimit, recordFailure } from '../utils/failureLimiter';
import { generateTotpSecret, otpauthUri, verifyTotp } from '../utils/totp';
import { safeEqualString } from '../utils/internalSecret';
import { notifyDashboard } from '../services/dashboardEvents';
import { handleTokenReuse, recordRotation } from '../services/tokenReuse';
import {
  SessionRecord,
  SessionPolicy,
  clearSession,
  getTrustedIps,
  trustIp,
  completeStepUp,
  computeRisk,
  getSession,
  getSessionPolicy,
  lockSession,
  registerStepUpFailure,
} from '../services/sessionGuard';
import {
  newIdentitySchema,
  checkIdentitySchema,
  heartbeatSchema,
  regenerateSchema,
  killSchema,
  stepUpSchema,
  parseBody,
} from './validation';

const router = Router();

// ── Limites ───────────────────────────────────────────────────
// Janela de 60 s. Todos falham fechado se o Redis estiver indisponível.
const CHECK_LIMIT_PER_IP = 10;
const CRED_ROUTE_LIMIT_PER_IP = 10;
const CRED_FAILURES_PER_IDENTITY = 5;
const LIMIT_WINDOW_S = 60;

/**
 * Rotas que recebem identityId + privateKey (heartbeat, regenerate, kill).
 * Bloqueia por IP (tentativas) e por identidade (falhas): sem isso elas eram
 * um oráculo de chave privada fora do motor de defesa.
 */
async function credentialRouteBlocked(route: string, ip: string, identityId: string) {
  if (await isOverLimit(`credrl:${route}:${ip}`, CRED_ROUTE_LIMIT_PER_IP, LIMIT_WINDOW_S)) {
    return true;
  }
  return isBlocked(`credfail:${identityId}`, CRED_FAILURES_PER_IDENTITY);
}

/** Falha de credencial: conta a falha e responde igual a qualquer outra falha. */
async function credentialFailure(res: Response, identityId: string, startMs: number) {
  await recordFailure(`credfail:${identityId}`, LIMIT_WINDOW_S);
  await normalizeResponseTime(startMs, 120 + Math.random() * 30);
  return res.status(200).json(STEALTH_RESPONSE);
}

// ── Bloqueio de sessão (step-up) ──────────────────────────────
function challengeBody(session: SessionRecord, policy: SessionPolicy, hasMfa: boolean) {
  return {
    success: true,
    action: 'STEP_UP_REQUIRED',
    reason: 'risk_detected',
    challengeId: session.challengeId,
    methods: policy.requireMfa && hasMfa ? ['reauth', 'mfa'] : ['reauth'],
    endpoint: '/identity/step-up',
  };
}

/** true quando a sessão está travada (desafio pendente ou bloqueada). */
async function sessionLocked(identityId: string): Promise<boolean> {
  const s = await getSession(identityId);
  return !!s && (s.state === 'challenge' || s.state === 'blocked');
}

/** Cria um token externo novo (cifrado) para a credencial e devolve o id. */
async function issueExternalToken(
  identityId: string,
  privateKey: string,
  expiresAt: number
): Promise<string> {
  const next = crypto.randomBytes(32).toString('hex');
  const ttl = Math.max(1, Math.floor((expiresAt - Date.now()) / 1000));
  await db.set(`ext:${next}`, sealToken(encodeCredentialToken(identityId, privateKey), next), ttl);
  return next;
}

// ── Timing protection helper ──────────────────────────────────
async function normalizeResponseTime(startMs: number, targetMs: number): Promise<void> {
  const elapsed = Date.now() - startMs;
  if (elapsed < targetMs) await new Promise((r) => setTimeout(r, targetMs - elapsed));
}

// ─────────────────────────────────────────────
//  TOKEN ENCODING — Stealth Credential Layer
// ─────────────────────────────────────────────

function encodeCredentialToken(identityId: string, privateKey: string): string {
  const payload = JSON.stringify({
    i: identityId,
    k: privateKey,
    t: Date.now(),
    v: 1,
  });
  return Buffer.from(payload).toString('base64url');
}

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
// ─────────────────────────────────────────────

const STEALTH_FAILURE = {
  success: true,
  status: 'ok',
  mode: 'stealth',
} as const;

function randomFailureStatus(): number {
  return 200;
}

async function stealthDelay(minMs = 80, maxMs = 120): Promise<void> {
  const delay = Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
  await new Promise((resolve) => setTimeout(resolve, delay));
}

const STEALTH_RESPONSE = { success: true, status: 'ok', mode: 'stealth' } as const;

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
async function getGeoAndVPN(
  ip: string
): Promise<{ country: string | null; city: string | null; isVPN: boolean; isDatacenter: boolean }> {
  try {
    if (
      !ip ||
      ip === 'unknown' ||
      ip.startsWith('192.168') ||
      ip.startsWith('10.') ||
      ip === '127.0.0.1'
    ) {
      return { country: 'Local', city: 'Local', isVPN: false, isDatacenter: false };
    }
    // Sem chave HTTPS configurada não consultamos serviço externo: o IP do
    // cliente não deve trafegar em HTTP puro (o plano gratuito da ip-api não tem TLS).
    const geoKey = process.env.IPAPI_PRO_KEY;
    if (!geoKey) return { country: null, city: null, isVPN: false, isDatacenter: false };
    const r = await fetch(
      `https://pro.ip-api.com/json/${encodeURIComponent(ip)}?key=${encodeURIComponent(geoKey)}&fields=country,city,status,proxy,hosting`,
      { signal: AbortSignal.timeout(2500) }
    );
    const d = (await r.json()) as Record<string, unknown>;
    if (d.status !== 'success')
      return { country: null, city: null, isVPN: false, isDatacenter: false };
    return {
      country: (d.country as string) || null,
      city: (d.city as string) || null,
      isVPN: d.proxy === true,
      isDatacenter: d.hosting === true,
    };
  } catch {
    return { country: null, city: null, isVPN: false, isDatacenter: false };
  }
}

// ─────────────────────────────────────────────
//  POST /identity/new
// ─────────────────────────────────────────────
router.post(
  '/new',
  requireApiKey,
  checkIdentityCreationLimit,
  async (req: Request, res: Response) => {
    try {
      const parsed = parseBody(newIdentitySchema, req.body);
      if (!parsed.success) return res.status(400).json(STEALTH_RESPONSE);
      const { paranoiaLevel } = parsed.data;

      const result = await createIdentity(paranoiaLevel);

      if (req.apiKey?.userId) {
        result.identity.userId = req.apiKey.userId;
        await db.setIdentity(result.identity.id, result.identity);
      }

      // MFA (TOTP): emitido nos níveis cuja política exige. O segredo aparece
      // aqui uma única vez e fica cifrado no Redis.
      let mfa: { secret: string; otpauthUri: string } | undefined;
      if (getSessionPolicy(paranoiaLevel).requireMfa) {
        const secret = generateTotpSecret();
        result.identity.mfaSecret = sealToken(secret, result.identity.id);
        await db.setIdentity(result.identity.id, result.identity);
        mfa = { secret, otpauthUri: otpauthUri(result.identity.id, secret) };
      }

      const credentialToken = encodeCredentialToken(result.identity.id, result.privateKey);

      const userId = req.apiKey?.userId;
      if (userId) {
        const dashUrl = process.env.DASHBOARD_URL || 'https://rekuway-dashboard.vercel.app';
        fetch(`${dashUrl}/api/keys/event`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-internal-secret': process.env.INTERNAL_SECRET || '',
          },
          body: JSON.stringify({
            userId,
            type: 'IDENTITY_CREATED',
            severity: 'LOW',
            description: `New identity created: ${result.identity.id} [${paranoiaLevel}]`,
            blocked: false,
          }),
          signal: AbortSignal.timeout(3000),
        }).catch(() => {});
      }

      const externalToken = crypto.randomBytes(32).toString('hex');
      const ttlSeconds = Math.max(1, Math.floor((result.identity.expiresAt - Date.now()) / 1000));
      // Fail-closed: se não der para guardar o token criptografado, não emitimos token.
      await db.set(`ext:${externalToken}`, sealToken(credentialToken, externalToken), ttlSeconds);

      await stealthDelay();
      res.status(200).json({
        success: true,
        status: 'created',
        mode: 'stealth',
        token: externalToken,
        expiresAt: result.identity.expiresAt,
        ...(mfa ? { mfa } : {}),
      });
    } catch (error) {
      safeError('[API] Error creating identity:', error);
      res.status(200).json(STEALTH_RESPONSE);
    }
  }
);

// ─────────────────────────────────────────────
//  POST /identity/check
// ─────────────────────────────────────────────
router.post('/check', async (req: Request, res: Response) => {
  const reqStart = Date.now();
  const clientIP = getClientIp(req);

  if (await isOverLimit(`rl:check:${clientIP}`, CHECK_LIMIT_PER_IP, LIMIT_WINDOW_S)) {
    return res.status(200).json(STEALTH_RESPONSE);
  }

  try {
    const parsed = parseBody(checkIdentitySchema, req.body);
    if (!parsed.success) {
      await new Promise((r) => setTimeout(r, 80 + Math.floor(Math.random() * 40)));
      return res.status(200).json(STEALTH_RESPONSE);
    }

    const { token: extToken } = parsed.data;
    const userAgent = req.headers['user-agent'] || '';

    let identityId: string = parsed.data.identityId || '';
    let privateKey: string = parsed.data.privateKey || '';

    if (extToken) {
      try {
        const stored = await db.get(`ext:${extToken}`);
        const realToken = typeof stored === 'string' && stored ? openToken(stored, extToken) : null;
        if (realToken) {
          const decoded = decodeCredentialToken(realToken);
          if (decoded) {
            identityId = decoded.identityId;
            privateKey = decoded.privateKey;
          }
        }
      } catch {}
    }

    // Token já rotacionado sendo apresentado de novo: possível roubo. A resposta
    // continua uniforme; o efeito (identidade destruída + alerta) é interno.
    if (extToken && !identityId) {
      try {
        await handleTokenReuse(extToken, { ip: clientIP, userAgent: String(userAgent) });
      } catch (error) {
        safeError('[CHECK] Token reuse handling failed', error);
      }
    }

    if (!identityId || !privateKey) {
      await new Promise((r) => setTimeout(r, 80 + Math.floor(Math.random() * 40)));
      return res.status(200).json(STEALTH_RESPONSE);
    }

    let identity = await db.getIdentity(identityId);

    if (!identity || !identity.isAlive) {
      await sendStealthFailure(res, 'NOT_FOUND', identityId);
      return;
    }

    if (identity.paranoiaLevel === 'deadman') {
      const config = paranoiaConfig.deadman;
      const deadmanTimerMs = (config.deadmanTimer || 60) * 1000;
      const lastHeartbeat = identity.lastHeartbeat || identity.lastCheckIn || identity.createdAt;
      const timeSince = Date.now() - lastHeartbeat;

      if (timeSince > deadmanTimerMs) {
        await killIdentity(identityId);
        const dashUrl = process.env.DASHBOARD_URL || 'https://rekuway-dashboard.vercel.app';
        fetch(`${dashUrl}/api/keys/event`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-internal-secret': process.env.INTERNAL_SECRET || '',
          },
          body: JSON.stringify({
            userId: identity?.userId,
            type: 'ATTACK_BLOCKED',
            severity: 'CRITICAL',
            description: `Deadman timer expired — identity killed: ${identityId}`,
            blocked: true,
            ipAddress: clientIP,
            userAgent,
            metadata: await getGeoAndVPN(clientIP),
          }),
          signal: AbortSignal.timeout(3000),
        }).catch(() => {});
        await sendStealthFailure(res, 'DEADMAN_EXPIRED', identityId);
        return;
      }
    }

    const config = paranoiaConfig[identity.paranoiaLevel];

    if (typeof identity.totalAttempts === 'undefined') identity.totalAttempts = identity.attempts;
    if (typeof identity.regenerationCount === 'undefined') identity.regenerationCount = 0;
    if (typeof identity.attemptsAfterRegenerate === 'undefined')
      identity.attemptsAfterRegenerate = 0;

    const features = await extractFeatures(identity, clientIP, userAgent);
    await trackEndpoint(identityId, 'check');
    const aiAnalysis = await analyzeWithAI(features);
    // IA do serviço externo: consultiva. Roda em paralelo à validação e só é
    // aguardada no caminho de falha. Nunca lança: indisponível/timeout → null.
    const railwayAiPromise = (async () =>
      analyzeWithRailwayAI(convertToRailwayFeatures(features)))().catch(() => null);
    const validatedIdentity = await validateIdentity(identityId, privateKey);

    if (!validatedIdentity) {
      fetch(
        `${process.env.DASHBOARD_URL || 'https://rekuway-dashboard.vercel.app'}/api/keys/event`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-internal-secret': process.env.INTERNAL_SECRET || '',
          },
          body: JSON.stringify({
            userId: identity?.userId,
            type: 'ATTACK_BLOCKED',
            severity: 'HIGH',
            description: `Invalid private key attempt on identity: ${identityId}`,
            blocked: true,
            ipAddress: clientIP,
            userAgent,
            metadata: await getGeoAndVPN(clientIP),
          }),
          signal: AbortSignal.timeout(3000),
        }
      ).catch(() => {});
      await normalizeResponseTime(reqStart, 80 + Math.random() * 40);
      await sendStealthFailure(res, DefensiveAction.ALLOW, identityId);
      return;
    }

    const isValidSignature = validatedIdentity.isValidSignature;

    if (isValidSignature === true) {
      // ── Bloqueio de sessão: credencial válida, mas o motor viu risco ──
      const policy = getSessionPolicy(identity.paranoiaLevel);
      const session = await getSession(identityId);
      if (session?.state === 'blocked') {
        return res.json({
          success: true,
          action: 'BLOCKED',
          retryAfter: Math.max(1, Math.ceil(((session.blockedUntil || 0) - Date.now()) / 1000)),
        });
      }
      if (session?.state === 'challenge') {
        return res.json(challengeBody(session, policy, !!identity.mfaSecret));
      }
      if (session?.state !== 'trusted') {
        const railway = await Promise.race([
          railwayAiPromise,
          new Promise<null>((r) => setTimeout(() => r(null), 300)),
        ]);
        const trusted = await getTrustedIps(identityId);
        const risk = computeRisk({
          priorFailures: identity.attempts || 0,
          ipChanged: trusted.length > 0 && !trusted.includes(clientIP),
          fingerprintChange: features.fingerprintChange,
          geolocationChange: features.geolocationChange,
          isPostRegeneration: features.isPostRegeneration,
          aiScore: Math.max(aiAnalysis?.riskAnalysis.threatScore ?? 0, railway?.threatScore ?? 0),
        });
        if (risk.score >= policy.challengeAt) {
          const locked = await lockSession(identityId, risk);
          safeLog('[SESSION] Locked — step-up required', {
            identityId,
            level: identity.paranoiaLevel,
            risk: risk.score,
            reasons: risk.reasons,
          });
          notifyDashboard({
            userId: identity.userId,
            type: 'SESSION_LOCKED',
            severity: 'HIGH',
            description: `Session locked, step-up required on identity: ${identityId} [${identity.paranoiaLevel}]`,
            blocked: true,
            ipAddress: clientIP,
            metadata: { riskScore: risk.score, reasons: risk.reasons },
          });
          return res.json(challengeBody(locked, policy, !!identity.mfaSecret));
        }
      }

      // Passou pela porta de sessão: este IP vira (ou continua sendo) confiável.
      await trustIp(identityId, clientIP, identity.expiresAt);

      if (identity.paranoiaLevel === 'deadman') {
        const now = Date.now();
        identity.lastHeartbeat = now;
        identity.lastCheckIn = now;
      }
      identity.attempts = 0;
      identity.attemptsAfterRegenerate = 0;
      await db.set(`identity:${identityId}`, identity);

      // Rotação só após validação bem-sucedida, e o novo token vai na resposta.
      // (Antes o token antigo era invalidado e o novo nunca chegava ao cliente.)
      let rotatedToken: string | undefined;
      if (extToken) {
        try {
          const stored = await db.get(`ext:${extToken}`);
          const plain = typeof stored === 'string' && stored ? openToken(stored, extToken) : null;
          if (plain) {
            const next = crypto.randomBytes(32).toString('hex');
            const ttlRem = Math.max(1, Math.floor((identity.expiresAt - Date.now()) / 1000));
            await db.set(`ext:${next}`, sealToken(plain, next), ttlRem);
            await db.set(`ext:${extToken}`, '', 1);
            await recordRotation(extToken, identityId, identity.expiresAt);
            rotatedToken = next;
            safeLog('[CHECK] Token rotated', { identityId });
          }
        } catch (error) {
          safeError('[CHECK] Token rotation failed — keeping current token', error);
        }
      }

      return res.json({
        success: true,
        action: 'ALLOWED',
        ...(rotatedToken ? { token: rotatedToken } : {}),
        identity: {
          id: validatedIdentity.id,
          publicKey: validatedIdentity.publicKey,
          paranoiaLevel: validatedIdentity.paranoiaLevel,
          expiresAt: validatedIdentity.expiresAt,
        },
      });
    }

    identity = await db.getIdentity(identityId);
    if (!identity) {
      await sendStealthFailure(res, 'NOT_FOUND', identityId);
      return;
    }

    identity.attempts = (identity.attempts || 0) + 1;
    identity.totalAttempts = (identity.totalAttempts || 0) + 1;
    identity.lastAttemptAt = Date.now();
    if (identity.regenerationCount > 0) {
      identity.attemptsAfterRegenerate = (identity.attemptsAfterRegenerate || 0) + 1;
    }
    await db.set(`identity:${identityId}`, identity);

    const ruleBasedAction: DefensiveAction = computeRuleBasedAction(
      identity,
      config.regenerateThreshold
    );

    const actionPriority: Record<DefensiveAction, number> = {
      [DefensiveAction.KILL]: 4,
      [DefensiveAction.LIE]: 3,
      [DefensiveAction.REGENERATE]: 2,
      [DefensiveAction.ALLOW]: 1,
    };

    // Camada local de regras (comportamento anterior preservado): a heurística
    // local (aiClient) continua podendo escalar a ação das regras.
    const localAiRecommendation = aiAnalysis?.riskAnalysis.recommendedAction;
    const localAiAction: DefensiveAction =
      !localAiRecommendation || localAiRecommendation === 'ALLOW'
        ? DefensiveAction.ALLOW
        : (localAiRecommendation as DefensiveAction);
    const rulesAction: DefensiveAction =
      actionPriority[localAiAction] > actionPriority[ruleBasedAction]
        ? localAiAction
        : ruleBasedAction;

    // IA externa (Railway): só aconselha. combineDecisionsV3 devolve sempre a
    // ação das regras e registra divergências no auditLog. Se a IA não
    // respondeu (null), decide só pelas regras.
    let finalAction: DefensiveAction = rulesAction;
    try {
      const railwayAI = await railwayAiPromise;
      const decision = await combineDecisionsV3({
        ruleBasedAction: rulesAction,
        aiRecommendation: railwayAI ? railwayAI.recommendedAction : null,
        validationSuccessful: false,
        threatScore: railwayAI?.threatScore ?? 0,
        confidence: railwayAI?.confidence ?? 'low',
        topFactors: railwayAI?.topFactors ?? [],
        identityId,
      });
      finalAction = decision.action;
      if (decision.aiDisagreement) {
        safeLog('[AI_DIVERGENCE]', { identityId, auditLog: decision.auditLog });
      }
    } catch (error) {
      safeError('[DECISION] combineDecisionsV3 failed — using rules only', error);
    }

    // ── KILL ─────────────────────────────────────────────────
    if (finalAction === DefensiveAction.KILL) {
      await killIdentity(identityId);
      fetch(
        `${process.env.DASHBOARD_URL || 'https://rekuway-dashboard.vercel.app'}/api/keys/event`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-internal-secret': process.env.INTERNAL_SECRET || '',
          },
          body: JSON.stringify({
            userId: identity.userId,
            type: 'ATTACK_BLOCKED',
            severity: 'CRITICAL',
            description: `Identity KILLED after attacks: ${identityId}`,
            blocked: true,
            ipAddress: clientIP,
            userAgent,
            metadata: await getGeoAndVPN(clientIP),
          }),
          signal: AbortSignal.timeout(3000),
        }
      ).catch(() => {});
      await normalizeResponseTime(reqStart, 120 + Math.random() * 30);
      await sendStealthFailure(res, DefensiveAction.KILL, identityId);
      return;
    }

    // ── LIE ──────────────────────────────────────────────────
    if (finalAction === DefensiveAction.LIE) {
      const lieEvent = {
        eventId: crypto.randomUUID(),
        timestamp: Date.now(),
        identityIdHash: crypto.createHash('sha256').update(identityId).digest('hex').slice(0, 16),
        action: 'LIE',
        lieStrategy: 'fake_success',
        actor: {
          ip: clientIP,
          forwardedFor: req.headers['x-forwarded-for'] || null,
          userAgent: userAgent || 'unknown',
          device: /mobile/i.test(userAgent)
            ? 'mobile'
            : /bot|curl|python|go-http/i.test(userAgent)
              ? 'bot'
              : 'desktop',
        },
        context: {
          attemptNumber: identity.attempts || 0,
          totalAttempts: identity.totalAttempts || 0,
          afterRegeneration: (identity.regenerationCount || 0) > 0,
          regenerations: identity.regenerationCount || 0,
        },
        risk: {
          level:
            (identity.attempts || 0) > 5
              ? 'CRITICAL'
              : (identity.attempts || 0) > 3
                ? 'HIGH'
                : 'MEDIUM',
          score: Math.min(
            100,
            (identity.attempts || 0) * 15 + (identity.regenerationCount || 0) * 20
          ),
        },
        fingerprint: crypto
          .createHash('sha256')
          .update(clientIP + (userAgent || ''))
          .digest('hex')
          .slice(0, 32),
        decision: {
          reason: 'tentativa suspeita — sistema aplicou deception',
          nextAction: (identity.attempts || 0) >= 3 ? 'KILL' : 'MONITOR',
        },
      };
      try {
        await db.set(`lie_event:${lieEvent.eventId}`, lieEvent, 86400);
      } catch {}
      fetch(
        `${process.env.DASHBOARD_URL || 'https://rekuway-dashboard.vercel.app'}/api/keys/event`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-internal-secret': process.env.INTERNAL_SECRET || '',
          },
          body: JSON.stringify({
            userId: identity?.userId,
            type: 'ATTACK_BLOCKED',
            severity: 'HIGH',
            description: `Attack deceived [LIE] on identity: ${identityId}`,
            blocked: true,
            ipAddress: clientIP,
            userAgent,
            metadata: await getGeoAndVPN(clientIP),
          }),
          signal: AbortSignal.timeout(3000),
        }
      ).catch(() => {});
      await normalizeResponseTime(reqStart, 120 + Math.random() * 30);
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

      const newIdentity = newIdentityResult.identity;
      newIdentity.totalAttempts = identity.totalAttempts;
      newIdentity.regenerationCount = (identity.regenerationCount || 0) + 1;
      newIdentity.attemptsAfterRegenerate = 0;
      newIdentity.userId = identity.userId;
      await db.set(`identity:${newIdentity.id}`, newIdentity);

      safeLog('[DEFENSE] REGENERATE triggered — new identity created', {
        oldId: identityId,
        newId: newIdentity.id,
      });

      fetch(
        `${process.env.DASHBOARD_URL || 'https://rekuway-dashboard.vercel.app'}/api/keys/event`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-internal-secret': process.env.INTERNAL_SECRET || '',
          },
          body: JSON.stringify({
            userId: identity.userId || req.apiKey?.userId,
            type: 'IDENTITY_ROTATION',
            severity: 'MEDIUM',
            description: `Identity rotated: ${identityId} → ${newIdentity.id}`,
            blocked: false,
          }),
          signal: AbortSignal.timeout(3000),
        }
      ).catch(() => {});
      await normalizeResponseTime(reqStart, 120 + Math.random() * 30);
      await sendStealthFailure(res, DefensiveAction.REGENERATE, identityId);
      return;
    }

    // ── ALLOW (falha simples) ─────────────────────────────────
    fetch(`${process.env.DASHBOARD_URL || 'https://rekuway-dashboard.vercel.app'}/api/keys/event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-internal-secret': process.env.INTERNAL_SECRET || '',
      },
      body: JSON.stringify({
        userId: identity?.userId,
        type: 'ATTACK_BLOCKED',
        severity: 'MEDIUM',
        description: `Failed attempt [ALLOW] on identity: ${identityId}`,
        blocked: true,
        ipAddress: clientIP,
        userAgent,
        metadata: await getGeoAndVPN(clientIP),
      }),
      signal: AbortSignal.timeout(3000),
    }).catch(() => {});
    await normalizeResponseTime(reqStart, 120 + Math.random() * 30);
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
  const reqStart = Date.now();
  try {
    const parsed = parseBody(heartbeatSchema, req.body);
    if (!parsed.success) return res.status(200).json(STEALTH_RESPONSE);
    const { identityId, privateKey } = parsed.data;

    if (await credentialRouteBlocked('heartbeat', getClientIp(req), identityId)) {
      return credentialFailure(res, identityId, reqStart);
    }

    const identity = await db.getIdentity(identityId);

    if (!identity || !identity.isAlive) {
      return credentialFailure(res, identityId, reqStart);
    }

    const validatedIdentity = await validateIdentity(identityId, privateKey);

    if (!validatedIdentity || !validatedIdentity.isValidSignature) {
      return credentialFailure(res, identityId, reqStart);
    }

    // Sessão travada não renova o prazo do deadman (evita manter viva com credencial roubada).
    if (await sessionLocked(identityId)) {
      return credentialFailure(res, identityId, reqStart);
    }

    if (identity.paranoiaLevel !== 'deadman') {
      return res.status(400).json({ success: false, error: 'Invalid request' });
    }

    // Heartbeat de um IP novo é o caminho de quem roubou a credencial para manter
    // a identidade viva: o motor trava a sessão em vez de renovar o prazo.
    const heartbeatIp = getClientIp(req);
    const trustedIps = await getTrustedIps(identityId);
    const hbRisk = computeRisk({
      priorFailures: 0,
      ipChanged: trustedIps.length > 0 && !trustedIps.includes(heartbeatIp),
      fingerprintChange: false,
      geolocationChange: false,
      isPostRegeneration: false,
      aiScore: 0,
    });
    if (hbRisk.score >= getSessionPolicy(identity.paranoiaLevel).challengeAt) {
      await lockSession(identityId, hbRisk);
      notifyDashboard({
        userId: identity.userId,
        type: 'SESSION_LOCKED',
        severity: 'HIGH',
        description: `Heartbeat from untrusted IP — session locked: ${identityId}`,
        blocked: true,
        ipAddress: heartbeatIp,
        metadata: { riskScore: hbRisk.score, reasons: hbRisk.reasons },
      });
      return credentialFailure(res, identityId, reqStart);
    }

    const updated = await updateHeartbeat(identityId);

    if (!updated) {
      return res.status(500).json({ success: false, error: 'Failed to update heartbeat' });
    }

    const config = paranoiaConfig.deadman;
    const now = Date.now();
    const nextDeadline = now + (config.deadmanTimer || 60) * 1000;

    res.json({
      success: true,
      identity: {
        id: identity.id,
        paranoiaLevel: identity.paranoiaLevel,
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
  const reqStart = Date.now();
  try {
    const parsed = parseBody(regenerateSchema, req.body);
    if (!parsed.success)
      return res.status(400).json({ success: false, error: 'Invalid request body' });
    const { identityId, privateKey } = parsed.data;

    if (await credentialRouteBlocked('regenerate', getClientIp(req), identityId)) {
      return credentialFailure(res, identityId, reqStart);
    }

    const validatedIdentity = await validateIdentity(identityId, privateKey);

    if (!validatedIdentity || !validatedIdentity.isValidSignature) {
      return credentialFailure(res, identityId, reqStart);
    }

    if (await sessionLocked(identityId)) {
      return credentialFailure(res, identityId, reqStart);
    }

    const newIdentity = await regenerateIdentity(identityId);

    if (!newIdentity) {
      return res.status(500).json({ success: false, error: 'Failed to regenerate identity' });
    }

    const credentialToken = encodeCredentialToken(newIdentity.identity.id, newIdentity.privateKey);

    res.json({
      success: true,
      token: credentialToken,
      exp: newIdentity.identity.expiresAt,
      lvl: newIdentity.identity.paranoiaLevel,
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
  const reqStart = Date.now();
  try {
    const parsed = parseBody(killSchema, req.body);
    if (!parsed.success)
      return res.status(400).json({ success: false, error: 'Invalid request body' });
    const { identityId, privateKey } = parsed.data;

    if (await credentialRouteBlocked('kill', getClientIp(req), identityId)) {
      return credentialFailure(res, identityId, reqStart);
    }

    const validatedIdentity = await validateIdentity(identityId, privateKey);

    if (!validatedIdentity || !validatedIdentity.isValidSignature) {
      return credentialFailure(res, identityId, reqStart);
    }

    const killed = await killIdentity(identityId);

    if (!killed) {
      return res.status(500).json({ success: false, error: 'Failed to destroy identity' });
    }

    await clearSession(identityId);
    res.json({ success: true });
  } catch (error) {
    safeError('[API] Error killing:', error);
    res.status(500).json({ success: false, error: 'Failed to destroy identity' });
  }
});

// ─────────────────────────────────────────────
//  POST /identity/step-up — destrava a sessão (credencial de novo + MFA)
// ─────────────────────────────────────────────
router.post('/step-up', async (req: Request, res: Response) => {
  const reqStart = Date.now();
  const clientIP = getClientIp(req);
  try {
    const parsed = parseBody(stepUpSchema, req.body);
    if (!parsed.success) {
      await normalizeResponseTime(reqStart, 120 + Math.random() * 30);
      return res.status(200).json(STEALTH_RESPONSE);
    }
    const { challengeId, code, token: extToken } = parsed.data;
    let identityId = parsed.data.identityId || '';
    let privateKey = parsed.data.privateKey || '';

    if (extToken) {
      const stored = await db.get(`ext:${extToken}`);
      const plain = typeof stored === 'string' && stored ? openToken(stored, extToken) : null;
      const decoded = plain ? decodeCredentialToken(plain) : null;
      if (decoded) {
        identityId = decoded.identityId;
        privateKey = decoded.privateKey;
      }
    }
    if (extToken && !identityId) {
      try {
        await handleTokenReuse(extToken, {
          ip: clientIP,
          userAgent: String(req.headers['user-agent'] || ''),
        });
      } catch (error) {
        safeError('[STEP-UP] Token reuse handling failed', error);
      }
    }
    if (!identityId || !privateKey) {
      await normalizeResponseTime(reqStart, 120 + Math.random() * 30);
      return res.status(200).json(STEALTH_RESPONSE);
    }

    if (await credentialRouteBlocked('stepup', clientIP, identityId)) {
      return credentialFailure(res, identityId, reqStart);
    }

    const identity = await db.getIdentity(identityId);
    if (!identity || !identity.isAlive) return credentialFailure(res, identityId, reqStart);

    const validated = await validateIdentity(identityId, privateKey);
    if (!validated || !validated.isValidSignature) {
      return credentialFailure(res, identityId, reqStart);
    }

    // A partir daqui a credencial é válida: só quem já a tem vê o estado do desafio.
    const session = await getSession(identityId);
    if (!session || session.state === 'trusted') {
      return credentialFailure(res, identityId, reqStart);
    }
    if (session.state === 'blocked') {
      return res.json({
        success: true,
        action: 'BLOCKED',
        retryAfter: Math.max(1, Math.ceil(((session.blockedUntil || 0) - Date.now()) / 1000)),
      });
    }
    if (!safeEqualString(session.challengeId, challengeId)) {
      return credentialFailure(res, identityId, reqStart);
    }

    const policy = getSessionPolicy(identity.paranoiaLevel);
    let counter: number | undefined;
    let mfaOk = true;
    if (policy.requireMfa && identity.mfaSecret) {
      const secret = openToken(identity.mfaSecret, identity.id);
      const v =
        secret && code
          ? verifyTotp(secret, code, Date.now(), { lastCounter: session.mfaLastCounter })
          : { ok: false as const, counter: undefined };
      mfaOk = v.ok;
      counter = v.counter;
    }

    if (!mfaOk) {
      const { record, outcome } = await registerStepUpFailure(identityId, session, policy);
      await normalizeResponseTime(reqStart, 120 + Math.random() * 30);
      if (outcome === 'kill') {
        await killIdentity(identityId);
        notifyDashboard({
          userId: identity.userId,
          type: 'SESSION_KILLED',
          severity: 'CRITICAL',
          description: `Step-up failed repeatedly — identity destroyed: ${identityId} [${identity.paranoiaLevel}]`,
          blocked: true,
          ipAddress: clientIP,
        });
        return res.status(200).json(STEALTH_RESPONSE);
      }
      if (outcome === 'blocked') {
        notifyDashboard({
          userId: identity.userId,
          type: 'SESSION_BLOCKED',
          severity: 'CRITICAL',
          description: `Step-up failed repeatedly — session blocked: ${identityId} [${identity.paranoiaLevel}]`,
          blocked: true,
          ipAddress: clientIP,
        });
        return res.json({
          success: true,
          action: 'BLOCKED',
          retryAfter: Math.max(1, Math.ceil(((record.blockedUntil || 0) - Date.now()) / 1000)),
        });
      }
      return res.json({
        success: true,
        action: 'STEP_UP_FAILED',
        remainingAttempts: policy.maxStepUpFailures - record.failures,
      });
    }

    await completeStepUp(identityId, session, policy, counter);
    // Novo ponto de partida: o IP/dispositivo validados passam a ser a referência.
    await trustIp(identityId, clientIP, identity.expiresAt, true);
    for (const prefix of ['ips', 'fingerprint', 'geo']) {
      await db.delete(`${prefix}:${identityId}`);
    }
    let newToken: string | undefined;
    if (extToken) {
      newToken = await issueExternalToken(identityId, privateKey, identity.expiresAt);
      await db.set(`ext:${extToken}`, '', 1);
      await recordRotation(extToken, identityId, identity.expiresAt);
    }
    safeLog('[SESSION] Step-up OK — session unlocked', { identityId });
    notifyDashboard({
      userId: identity.userId,
      type: 'SESSION_UNLOCKED',
      severity: 'LOW',
      description: `Step-up completed on identity: ${identityId}`,
      blocked: false,
      ipAddress: clientIP,
    });
    await normalizeResponseTime(reqStart, 120 + Math.random() * 30);
    return res.json({
      success: true,
      action: 'ALLOWED',
      ...(newToken ? { token: newToken } : {}),
      identity: {
        id: identity.id,
        paranoiaLevel: identity.paranoiaLevel,
        expiresAt: identity.expiresAt,
      },
    });
  } catch (error) {
    safeError('[API] Error in /step-up:', error);
    res.status(200).json(STEALTH_RESPONSE);
  }
});

// ─────────────────────────────────────────────
//  GET /identity/status/:id
// ─────────────────────────────────────────────
router.get('/status/:id', async (req: Request, res: Response) => {
  try {
    await db.getIdentity(req.params.id);
    return res.status(200).json(STEALTH_RESPONSE);
  } catch {
    return res.status(200).json(STEALTH_RESPONSE);
  }
});

export default router;
