import crypto from 'crypto';
import paranoiaConfig from '../config/paranoia.json';
import { db } from '../config/database';

/**
 * Bloqueio de sessão (step-up) — REKUWAY IDN
 *
 *   OPEN ──risco ≥ limiar do nível──▶ CHALLENGE ──falhas ≥ máximo──▶ BLOCKED
 *     ▲                                   │                             │
 *     └──── step-up OK (TRUSTED, carência) ┘      prazo vence ──────────┘ (volta a CHALLENGE)
 *
 * Em CHALLENGE a sessão fica travada: o token/chave continua válido, mas o
 * servidor não concede acesso até o usuário refazer a autenticação (credencial
 * apresentada de novo + código MFA, conforme o nível). Se o desafio falhar
 * repetidamente, a sessão é BLOQUEADA por um tempo (e no nível `deadman` a
 * identidade é destruída). A política é por nível de paranoia, em
 * config/paranoia.json → sessionPolicy.
 */

export type ParanoiaLevel = 'low' | 'medium' | 'high' | 'deadman';

export interface SessionPolicy {
  /** Risco (0-1) a partir do qual a sessão é travada e o step-up é exigido. */
  challengeAt: number;
  /** Exige código MFA (TOTP) além de apresentar a credencial de novo. */
  requireMfa: boolean;
  /** Falhas de step-up toleradas antes de bloquear. */
  maxStepUpFailures: number;
  blockSeconds: number;
  /** Depois de um step-up válido, o risco não é reavaliado por este tempo. */
  graceSeconds: number;
  /** O que fazer quando o desafio persiste em falhar. */
  onPersist: 'block' | 'kill';
}

export function getSessionPolicy(level: ParanoiaLevel): SessionPolicy {
  return paranoiaConfig[level].sessionPolicy as SessionPolicy;
}

// ── Risco ─────────────────────────────────────────────────────

export interface RiskSignals {
  /** Falhas antes deste acesso válido (sucesso após falhas = sinal clássico de força bruta). */
  priorFailures: number;
  /** IP atual difere dos IPs em que esta identidade já foi usada com sucesso. */
  ipChanged: boolean;
  fingerprintChange: boolean;
  geolocationChange: boolean;
  isPostRegeneration: boolean;
  /** Maior score consultivo disponível (heurística local e/ou IA externa), 0-1. */
  aiScore: number;
}

/**
 * Pontuação transparente e aditiva (teto 1). A IA pesa só 0,4 do próprio
 * score: ela aconselha, não decide sozinha.
 */
export function computeRisk(s: RiskSignals): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  let score = 0;
  const add = (points: number, reason: string) => {
    score += points;
    reasons.push(reason);
  };

  if (s.priorFailures > 0)
    add(Math.min(s.priorFailures, 3) * 0.15, `${s.priorFailures}_prior_failures`);
  if (s.ipChanged) add(0.4, 'ip_change');
  if (s.fingerprintChange) add(0.2, 'fingerprint_change');
  if (s.geolocationChange) add(0.2, 'geolocation_change');
  if (s.isPostRegeneration) add(0.1, 'post_regeneration');
  const ai = Math.max(0, Math.min(1, s.aiScore || 0));
  if (ai > 0) add(ai * 0.4, 'ai_advisory');

  return { score: Math.min(1, Number(score.toFixed(3))), reasons };
}

// ── Estado da sessão ──────────────────────────────────────────

export interface SessionRecord {
  state: 'challenge' | 'blocked' | 'trusted';
  challengeId: string;
  riskScore: number;
  reasons: string[];
  failures: number;
  blockCount: number;
  lockedAt: number;
  blockedUntil?: number;
  trustedUntil?: number;
  /** Último passo TOTP aceito (anti-replay). */
  mfaLastCounter?: number;
}

const key = (identityId: string) => `session:${identityId}`;
const SESSION_TTL_S = 24 * 3600;

/** Lê o estado e aplica as transições por tempo (bloqueio vencido, carência vencida). */
export async function getSession(
  identityId: string,
  now = Date.now()
): Promise<SessionRecord | null> {
  const rec = (await db.get(key(identityId))) as SessionRecord | null;
  if (!rec || typeof rec !== 'object') return null;

  if (rec.state === 'blocked' && rec.blockedUntil && now >= rec.blockedUntil) {
    // Fim do bloqueio: volta ao desafio (não ao acesso livre), com novo id e contador zerado.
    const next: SessionRecord = {
      ...rec,
      state: 'challenge',
      challengeId: crypto.randomUUID(),
      failures: 0,
      blockedUntil: undefined,
    };
    await db.set(key(identityId), next, SESSION_TTL_S);
    return next;
  }
  if (rec.state === 'trusted' && rec.trustedUntil && now >= rec.trustedUntil) {
    // Carência vencida: a sessão deixa de valer como confiável, mas o registro fica
    // (até o TTL) para preservar o último código MFA aceito e manter o anti-replay.
    return null;
  }
  return rec;
}

export async function lockSession(
  identityId: string,
  risk: { score: number; reasons: string[] },
  now = Date.now()
): Promise<SessionRecord> {
  const prev = (await db.get(key(identityId))) as SessionRecord | null;
  const rec: SessionRecord = {
    state: 'challenge',
    challengeId: crypto.randomUUID(),
    riskScore: risk.score,
    reasons: risk.reasons,
    failures: 0,
    blockCount: prev?.blockCount ?? 0,
    lockedAt: now,
    mfaLastCounter: prev?.mfaLastCounter,
  };
  await db.set(key(identityId), rec, SESSION_TTL_S);
  return rec;
}

/** Se o ataque persiste, cada novo bloqueio dura o dobro do anterior (teto de 24 h). */
export function blockDurationSeconds(policy: SessionPolicy, previousBlocks: number): number {
  return Math.min(policy.blockSeconds * 2 ** previousBlocks, 24 * 3600);
}

export type FailureOutcome = 'challenge' | 'blocked' | 'kill';

/** Decisão pura: aplica uma falha de step-up ao registro. */
export function applyStepUpFailure(
  rec: SessionRecord,
  policy: SessionPolicy,
  now = Date.now()
): { record: SessionRecord; outcome: FailureOutcome } {
  const failures = rec.failures + 1;
  if (failures < policy.maxStepUpFailures) {
    return { record: { ...rec, failures }, outcome: 'challenge' };
  }
  const record: SessionRecord = {
    ...rec,
    state: 'blocked',
    failures,
    blockCount: rec.blockCount + 1,
    blockedUntil: now + blockDurationSeconds(policy, rec.blockCount) * 1000,
  };
  return { record, outcome: policy.onPersist === 'kill' ? 'kill' : 'blocked' };
}

export async function registerStepUpFailure(
  identityId: string,
  rec: SessionRecord,
  policy: SessionPolicy,
  now = Date.now()
) {
  const result = applyStepUpFailure(rec, policy, now);
  await db.set(key(identityId), result.record, SESSION_TTL_S);
  return result;
}

export async function completeStepUp(
  identityId: string,
  rec: SessionRecord,
  policy: SessionPolicy,
  mfaCounter?: number,
  now = Date.now()
): Promise<SessionRecord> {
  const next: SessionRecord = {
    ...rec,
    state: 'trusted',
    failures: 0,
    blockedUntil: undefined,
    trustedUntil: now + policy.graceSeconds * 1000,
    mfaLastCounter: mfaCounter ?? rec.mfaLastCounter,
  };
  await db.set(key(identityId), next, SESSION_TTL_S);
  return next;
}

export async function clearSession(identityId: string): Promise<void> {
  await db.delete(key(identityId));
  await db.delete(trustedKey(identityId));
}

// ── IPs confiáveis ────────────────────────────────────────────
// Referência do "IP diferente": só IPs onde a identidade foi usada com sucesso
// (ou revalidada por step-up). Tentativas de atacantes não entram aqui, então
// ruído de fora não faz o dono parecer suspeito.
const trustedKey = (identityId: string) => `trusted_ips:${identityId}`;
const MAX_TRUSTED_IPS = 5;

export async function getTrustedIps(identityId: string): Promise<string[]> {
  const v = await db.get(trustedKey(identityId));
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

/** Marca o IP como confiável (primeiro uso = confiança inicial). `replace` zera a lista. */
export async function trustIp(
  identityId: string,
  ip: string,
  expiresAt: number,
  replace = false
): Promise<void> {
  const current = replace ? [] : await getTrustedIps(identityId);
  if (current.includes(ip) && !replace) return;
  const next = [...current.filter((x) => x !== ip), ip].slice(-MAX_TRUSTED_IPS);
  await db.set(
    trustedKey(identityId),
    next,
    Math.max(1, Math.floor((expiresAt - Date.now()) / 1000))
  );
}
