/**
 * Decision Engine V3 — REKUWAY IDN
 * IA OBSERVA, NUNCA DECIDE.
 * Logs sanitizados: NUNCA expõe privateKey, apiKey ou secrets.
 */

import { DefensiveAction } from '../models/Identity';
import { db } from '../config/database';
import { safeLog, safeError, safeWarn } from '../utils/sanitize';

export interface DecisionContext {
  ruleBasedAction: DefensiveAction;
  aiRecommendation: 'ALLOW' | 'REGENERATE' | 'LIE' | 'KILL' | null;
  validationSuccessful: boolean;
  threatScore: number;
  confidence: string;
  topFactors: string[];
  identityId: string;
}

export interface DecisionResult {
  action: DefensiveAction;
  reason: string;
  confidence: number;
  aiContribution: 'ignored' | 'agreed' | 'noted' | 'unavailable';
  auditLog: string[];
  aiDisagreement?: {
    aiWanted: string;
    rulesChose: string;
    reason: string;
  };
}

export async function combineDecisionsV3(context: DecisionContext): Promise<DecisionResult> {
  const {
    ruleBasedAction,
    aiRecommendation,
    validationSuccessful,
    threatScore,
    confidence,
    topFactors,
    identityId,
  } = context;

  const auditLog: string[] = [];

  const logCtx = {
    id:          identityId,
    rulesAction: ruleBasedAction,
    aiAction:    aiRecommendation || 'N/A',
    cryptoValid: validationSuccessful,
    threatScore: threatScore.toFixed(3),
  };

  safeLog(`[DECISION] ========================================`);
  safeLog(`[DECISION] Context:`, logCtx);

  auditLog.push(`Rules: ${ruleBasedAction}`);
  auditLog.push(`AI: ${aiRecommendation || 'N/A'}`);
  auditLog.push(`CryptoValid: ${validationSuccessful}`);

  // 🔒 REGRA #1: Validação criptográfica = ALLOW absoluto
  if (validationSuccessful && ruleBasedAction === DefensiveAction.ALLOW) {
    safeLog(`[DECISION] ✅ CRYPTOGRAPHIC VALIDATION PASSED → ALLOW`);
    auditLog.push('Reason: cryptographic_validation');

    await logDecision(identityId, {
      action:         'ALLOW',
      source:         'cryptographic_validation',
      aiRecommendation,
      aiWasIgnored:   aiRecommendation !== 'ALLOW',
      threatScore,
    });

    return {
      action:         DefensiveAction.ALLOW,
      reason:         'Valid cryptographic signature',
      confidence:     1.0,
      aiContribution: aiRecommendation ? 'ignored' : 'unavailable',
      auditLog,
    };
  }

  // 🤖 REGRA #2: IA indisponível = Rules sozinha
  if (!aiRecommendation) {
    safeLog(`[DECISION] ⚠️ AI unavailable → Rules only:`, { action: ruleBasedAction });
    auditLog.push('Reason: rules_only (AI unavailable)');

    await logDecision(identityId, {
      action:      ruleBasedAction,
      source:      'rules_only',
      aiAvailable: false,
    });

    return {
      action:         ruleBasedAction,
      reason:         buildReasonV3(ruleBasedAction, 'unavailable', []),
      confidence:     0.7,
      aiContribution: 'unavailable',
      auditLog,
    };
  }

  // 📏 REGRA #3: Rules SEMPRE vence
  const finalAction = ruleBasedAction;
  let aiContribution: 'ignored' | 'agreed' | 'noted';
  let aiDisagreement: DecisionResult['aiDisagreement'] | undefined;

  if (aiRecommendation === ruleBasedAction) {
    aiContribution = 'agreed';
    safeLog(`[DECISION] ✅ AI agreed:`, { action: finalAction, factors: topFactors.slice(0, 3) });
    auditLog.push(`AI agreed: ${finalAction}`);
  } else {
    aiContribution = 'noted';
    const severityMap: { [key: string]: number } = { ALLOW: 0, REGENERATE: 1, LIE: 2, KILL: 3 };
    const aiWantedHigher = severityMap[aiRecommendation] > severityMap[ruleBasedAction];

    if (aiWantedHigher) {
      safeLog(`[DECISION] 🚫 AI escalation OVERRIDDEN by Rules:`, {
        aiWanted:    aiRecommendation,
        rulesChose:  ruleBasedAction,
        threatScore: threatScore.toFixed(3),
      });
      aiDisagreement = {
        aiWanted:   aiRecommendation,
        rulesChose: ruleBasedAction,
        reason:     `AI detected higher threat (${threatScore.toFixed(2)}) but Rules are authority`,
      };
    } else {
      safeLog(`[DECISION] 📊 AI de-escalation noted, Rules maintained:`, {
        aiWanted:   aiRecommendation,
        rulesChose: ruleBasedAction,
      });
      aiDisagreement = {
        aiWanted:   aiRecommendation,
        rulesChose: ruleBasedAction,
        reason:     'Rules enforce stricter policy than AI suggested',
      };
    }
    auditLog.push(`AI disagreed: wanted ${aiRecommendation}, rules chose ${ruleBasedAction}`);
  }

  const finalConfidence = calculateConfidenceV3(aiContribution, threatScore, confidence);

  safeLog(`[DECISION] 🎯 Final:`, { action: finalAction, contribution: aiContribution, confidence: finalConfidence.toFixed(2) });
  safeLog(`[DECISION] ========================================`);

  await logDecision(identityId, {
    action:          finalAction,
    source:          'rules_with_ai_insight',
    ruleBasedAction,
    aiRecommendation,
    aiAgreed:        aiContribution === 'agreed',
    aiDisagreement,
    threatScore,
    topFactors,
    confidence:      finalConfidence,
  });

  return {
    action:         finalAction,
    reason:         buildReasonV3(finalAction, aiContribution, topFactors),
    confidence:     finalConfidence,
    aiContribution,
    auditLog,
    aiDisagreement,
  };
}

function calculateConfidenceV3(
  aiContribution: 'agreed' | 'noted' | 'ignored',
  _threatScore: number,
  aiConfidence: string
): number {
  if (aiContribution === 'agreed') return aiConfidence === 'high' ? 0.95 : 0.85;
  if (aiContribution === 'noted')  return 0.75;
  return 0.70;
}

function buildReasonV3(
  action: DefensiveAction,
  aiContribution: string,
  topFactors: string[]
): string {
  const reasons: { [key: string]: string } = {
    ALLOW:      'No significant threats detected by rules',
    REGENERATE: 'Rules triggered proactive regeneration',
    LIE:        'Rules confirmed attack pattern — returning deceptive data',
    KILL:       'Rules determined critical threat — identity destroyed',
  };

  let reason = reasons[action] || 'Security policy enforcement by rules';

  if (aiContribution === 'agreed' && topFactors.length > 0) {
    reason += ` (AI confirmed: ${topFactors.slice(0, 2).join(', ')})`;
  } else if (aiContribution === 'noted' && topFactors.length > 0) {
    reason += ` (AI noted: ${topFactors.slice(0, 2).join(', ')})`;
  }

  return reason;
}

async function logDecision(identityId: string, decision: Record<string, unknown>): Promise<void> {
  try {
    const logKey = `decision:${identityId}:${Date.now()}`;
    await db.set(logKey, JSON.stringify({ ...decision, timestamp: Date.now() }), 86400);
  } catch (error) {
    safeError('[DECISION] Failed to log decision:', error);
  }
}

/** @deprecated Use combineDecisionsV3 */
export function combineDecisions(
  ruleBasedAction: DefensiveAction,


): DefensiveAction {
  safeWarn('[DECISION] ⚠️ Using deprecated combineDecisions — upgrade to combineDecisionsV3');
  return ruleBasedAction;
}

export const combineDecisionsV2 = combineDecisionsV3;