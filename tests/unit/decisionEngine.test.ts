import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/config/database', () => ({
  db: { set: vi.fn().mockResolvedValue(true) },
}));

import paranoiaConfig from '../../src/config/paranoia.json';
import { DefensiveAction } from '../../src/models/Identity';
import { combineDecisionsV3, computeRuleBasedAction } from '../../src/services/decisionEngine';

type Level = 'low' | 'medium' | 'high' | 'deadman';
const LEVELS: Level[] = ['low', 'medium', 'high', 'deadman'];

const identity = (attempts: number, regenerationCount = 0, attemptsAfterRegenerate = 0) => ({
  attempts,
  regenerationCount,
  attemptsAfterRegenerate,
});

describe('computeRuleBasedAction — 4 níveis de paranoia', () => {
  it.each(LEVELS)('%s: ALLOW abaixo do limiar e REGENERATE ao atingi-lo', (level) => {
    const t = paranoiaConfig[level].regenerateThreshold;
    if (t > 1) {
      expect(computeRuleBasedAction(identity(t - 1), t)).toBe(DefensiveAction.ALLOW);
    }
    expect(computeRuleBasedAction(identity(0), t)).toBe(DefensiveAction.ALLOW);
    expect(computeRuleBasedAction(identity(t), t)).toBe(DefensiveAction.REGENERATE);
    expect(computeRuleBasedAction(identity(t + 5), t)).toBe(DefensiveAction.REGENERATE);
  });

  it.each(LEVELS)('%s: após regeneração, 1ª falha = LIE e 2ª = KILL', (level) => {
    const t = paranoiaConfig[level].regenerateThreshold;
    expect(computeRuleBasedAction(identity(t, 1, 0), t)).toBe(DefensiveAction.ALLOW);
    expect(computeRuleBasedAction(identity(t, 1, 1), t)).toBe(DefensiveAction.LIE);
    expect(computeRuleBasedAction(identity(t, 1, 2), t)).toBe(DefensiveAction.KILL);
    expect(computeRuleBasedAction(identity(t, 2, 7), t)).toBe(DefensiveAction.KILL);
  });

  it('os limiares de config/paranoia.json seguem 5/3/2/1', () => {
    expect(LEVELS.map((l) => paranoiaConfig[l].regenerateThreshold)).toEqual([5, 3, 2, 1]);
  });
});

describe('combineDecisionsV3 — IA consultiva, regras decidem', () => {
  const base = {
    validationSuccessful: false,
    threatScore: 0.9,
    confidence: 'high',
    topFactors: ['velocity'],
    identityId: 'id-1',
  };

  beforeEach(() => vi.clearAllMocks());

  it('IA indisponível: decide só pelas regras', async () => {
    const r = await combineDecisionsV3({
      ...base,
      ruleBasedAction: DefensiveAction.LIE,
      aiRecommendation: null,
    });
    expect(r.action).toBe(DefensiveAction.LIE);
    expect(r.aiContribution).toBe('unavailable');
  });

  it('IA pede KILL mas as regras dizem ALLOW: regras vencem e a divergência é registrada', async () => {
    const r = await combineDecisionsV3({
      ...base,
      ruleBasedAction: DefensiveAction.ALLOW,
      aiRecommendation: 'KILL',
    });
    expect(r.action).toBe(DefensiveAction.ALLOW);
    expect(r.aiDisagreement).toMatchObject({ aiWanted: 'KILL', rulesChose: 'ALLOW' });
    expect(r.auditLog.some((l) => l.startsWith('AI disagreed'))).toBe(true);
  });

  it('IA mais branda que as regras: regras mantidas', async () => {
    const r = await combineDecisionsV3({
      ...base,
      ruleBasedAction: DefensiveAction.KILL,
      aiRecommendation: 'ALLOW',
    });
    expect(r.action).toBe(DefensiveAction.KILL);
    expect(r.aiContribution).toBe('noted');
  });

  it('ALLOW da IA e ALLOWED das regras contam como concordância', async () => {
    const r = await combineDecisionsV3({
      ...base,
      ruleBasedAction: DefensiveAction.ALLOW,
      aiRecommendation: 'ALLOW',
    });
    expect(r.aiContribution).toBe('agreed');
    expect(r.aiDisagreement).toBeUndefined();
  });

  it.each([DefensiveAction.REGENERATE, DefensiveAction.LIE, DefensiveAction.KILL])(
    'IA igual às regras (%s): concordância',
    async (action) => {
      const r = await combineDecisionsV3({
        ...base,
        ruleBasedAction: action,
        aiRecommendation: action as 'REGENERATE' | 'LIE' | 'KILL',
      });
      expect(r.action).toBe(action);
      expect(r.aiContribution).toBe('agreed');
    }
  );

  it('assinatura válida com regras em ALLOW: ALLOW absoluto, IA ignorada', async () => {
    const r = await combineDecisionsV3({
      ...base,
      validationSuccessful: true,
      ruleBasedAction: DefensiveAction.ALLOW,
      aiRecommendation: 'KILL',
    });
    expect(r.action).toBe(DefensiveAction.ALLOW);
    expect(r.aiContribution).toBe('ignored');
  });
});
