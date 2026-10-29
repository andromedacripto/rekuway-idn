import { describe, expect, it, vi } from 'vitest';

vi.mock('../../src/config/database', () => ({ db: {} }));

import {
  SessionRecord,
  applyStepUpFailure,
  blockDurationSeconds,
  computeRisk,
  getSessionPolicy,
} from '../../src/services/sessionGuard';

const LEVELS = ['low', 'medium', 'high', 'deadman'] as const;
const base = {
  priorFailures: 0,
  ipChanged: false,
  fingerprintChange: false,
  geolocationChange: false,
  isPostRegeneration: false,
  aiScore: 0,
};
const rec = (over: Partial<SessionRecord> = {}): SessionRecord => ({
  state: 'challenge',
  challengeId: 'c',
  riskScore: 0.5,
  reasons: [],
  failures: 0,
  blockCount: 0,
  lockedAt: 0,
  ...over,
});
const triggers = (score: number) => LEVELS.map((l) => score >= getSessionPolicy(l).challengeAt);

describe('política de sessão por nível', () => {
  it('fica mais rígida a cada nível', () => {
    const p = LEVELS.map(getSessionPolicy);
    expect(p.map((x) => x.requireMfa)).toEqual([false, true, true, true]);
    expect(p.map((x) => x.onPersist)).toEqual(['block', 'block', 'block', 'kill']);
    for (let i = 1; i < p.length; i++) {
      expect(p[i].challengeAt).toBeLessThan(p[i - 1].challengeAt);
      expect(p[i].maxStepUpFailures).toBeLessThan(p[i - 1].maxStepUpFailures);
      expect(p[i].blockSeconds).toBeGreaterThan(p[i - 1].blockSeconds);
    }
  });
});

describe('computeRisk', () => {
  it('sem sinais, risco zero', () => {
    expect(computeRisk(base)).toEqual({ score: 0, reasons: [] });
  });

  it('soma sinais, lista motivos e limita a 1', () => {
    const r = computeRisk({
      priorFailures: 5,
      ipChanged: true,
      fingerprintChange: true,
      geolocationChange: true,
      isPostRegeneration: true,
      aiScore: 1,
    });
    expect(r.score).toBe(1);
    expect(r.reasons).toContain('ip_change');
    expect(r.reasons).toContain('ai_advisory');
  });

  it('a IA sozinha nunca passa de 0,4', () => {
    expect(computeRisk({ ...base, aiScore: 1 }).score).toBe(0.4);
  });

  it('IP novo sozinho trava medium, high e deadman, mas não low', () => {
    expect(triggers(computeRisk({ ...base, ipChanged: true }).score)).toEqual([
      false,
      true,
      true,
      true,
    ]);
  });

  it('IP novo + User-Agent diferente trava todos os níveis', () => {
    const r = computeRisk({ ...base, ipChanged: true, fingerprintChange: true });
    expect(triggers(r.score)).toEqual([true, true, true, true]);
  });

  it('um User-Agent diferente sozinho só trava o deadman', () => {
    expect(triggers(computeRisk({ ...base, fingerprintChange: true }).score)).toEqual([
      false,
      false,
      false,
      true,
    ]);
  });
});

describe('bloqueio', () => {
  it.each(LEVELS)('%s: bloqueia (ou destrói) exatamente na falha máxima', (level) => {
    const policy = getSessionPolicy(level);
    let current = rec();
    for (let i = 1; i < policy.maxStepUpFailures; i++) {
      const r = applyStepUpFailure(current, policy, 1000);
      expect(r.outcome).toBe('challenge');
      current = r.record;
    }
    const last = applyStepUpFailure(current, policy, 1000);
    expect(last.outcome).toBe(policy.onPersist === 'kill' ? 'kill' : 'blocked');
    expect(last.record.state).toBe('blocked');
    expect(last.record.blockedUntil).toBe(1000 + policy.blockSeconds * 1000);
    expect(last.record.blockCount).toBe(1);
  });

  it('cada novo bloqueio dura o dobro, com teto de 24 h', () => {
    const p = getSessionPolicy('high');
    expect(blockDurationSeconds(p, 0)).toBe(p.blockSeconds);
    expect(blockDurationSeconds(p, 1)).toBe(p.blockSeconds * 2);
    expect(blockDurationSeconds(p, 2)).toBe(p.blockSeconds * 4);
    expect(blockDurationSeconds(p, 30)).toBe(24 * 3600);
  });
});
