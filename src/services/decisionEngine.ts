/**
 * Decision Engine V3 - IA OBSERVA, NUNCA DECIDE
 * 
 * FILOSOFIA CRÍTICA:
 * - Validações criptográficas bem-sucedidas NUNCA são sobrescritas
 * - IA fornece insights, mas Rules são SEMPRE a autoridade
 * - IA pode concordar, discordar ou estar indisponível
 * - Toda discordância é registrada para análise
 * 
 * GARANTIAS:
 * - Zero falsos positivos em validações bem-sucedidas
 * - Latência < 10ms (decision apenas)
 * - Auditabilidade completa
 * - IA NUNCA escala decisões
 */

import { DefensiveAction } from '../models/Identity';
import { db } from '../config/database';

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

/**
 * LÓGICA PRINCIPAL - IA NUNCA VENCE
 * 
 * Fluxo de decisão:
 * 1. Validação criptográfica OK → ALLOW (IA totalmente ignorada)
 * 2. IA indisponível → Rules decide sozinha
 * 3. IA discorda → Rules SEMPRE vence, mas registra discordância
 * 4. IA concorda → Registra concordância para auditoria
 */
export async function combineDecisionsV3(context: DecisionContext): Promise<DecisionResult> {
  const {
    ruleBasedAction,
    aiRecommendation,
    validationSuccessful,
    threatScore,
    confidence,
    topFactors,
    identityId
  } = context;

  const auditLog: string[] = [];
  
  auditLog.push(`[DECISION] ========================================`);
  auditLog.push(`[DECISION] Identity: ${identityId}`);
  auditLog.push(`[DECISION] Rules Decision: ${ruleBasedAction}`);
  auditLog.push(`[DECISION] AI Recommendation: ${aiRecommendation || 'N/A'}`);
  auditLog.push(`[DECISION] Cryptographic Valid: ${validationSuccessful}`);
  auditLog.push(`[DECISION] AI Threat Score: ${threatScore.toFixed(3)}`);

  // 🔒 REGRA #1: Validação criptográfica = ALLOW absoluto
  if (validationSuccessful && ruleBasedAction === DefensiveAction.ALLOW) {
    auditLog.push('[DECISION] ✅ CRYPTOGRAPHIC VALIDATION PASSED');
    auditLog.push('[DECISION] 🎯 Final Action: ALLOW (AI opinion irrelevant)');
    auditLog.push('[DECISION] ========================================');
    
    await logDecision(identityId, {
      action: 'ALLOW',
      source: 'cryptographic_validation',
      aiRecommendation,
      aiWasIgnored: aiRecommendation !== 'ALLOW',
      threatScore
    });

    auditLog.forEach(log => console.log(log));

    return {
      action: DefensiveAction.ALLOW,
      reason: 'Valid cryptographic signature',
      confidence: 1.0,
      aiContribution: aiRecommendation ? 'ignored' : 'unavailable',
      auditLog
    };
  }

  // 🤖 REGRA #2: IA não disponível = Rules sozinha
  if (!aiRecommendation) {
    auditLog.push('[DECISION] ⚠️ AI unavailable');
    auditLog.push(`[DECISION] 🎯 Final Action: ${ruleBasedAction} (Rules only)`);
    auditLog.push('[DECISION] ========================================');

    await logDecision(identityId, {
      action: ruleBasedAction,
      source: 'rules_only',
      aiAvailable: false
    });

    auditLog.forEach(log => console.log(log));
    
    return {
      action: ruleBasedAction,
      reason: buildReasonV3(ruleBasedAction, 'unavailable', []),
      confidence: 0.7,
      aiContribution: 'unavailable',
      auditLog
    };
  }

  // 📏 REGRA #3: Rules SEMPRE vence
  const finalAction = ruleBasedAction;
  
  let aiContribution: 'ignored' | 'agreed' | 'noted';
  let aiDisagreement: DecisionResult['aiDisagreement'] | undefined;

  if (aiRecommendation === ruleBasedAction) {
    aiContribution = 'agreed';
    auditLog.push(`[DECISION] ✅ AI agreed with Rules: ${finalAction}`);
    auditLog.push(`[DECISION]    AI Factors: ${topFactors.slice(0, 3).join(', ')}`);
  } else {
    aiContribution = 'noted';
    
    const severityMap: { [key: string]: number } = {
      'ALLOW': 0,
      'REGENERATE': 1,
      'LIE': 2,
      'KILL': 3
    };

    const aiWantedHigher = severityMap[aiRecommendation] > severityMap[ruleBasedAction];
    const aiWantedLower = severityMap[aiRecommendation] < severityMap[ruleBasedAction];

    if (aiWantedHigher) {
      auditLog.push(`[DECISION] 🚫 AI wanted to ESCALATE: ${ruleBasedAction} → ${aiRecommendation}`);
      auditLog.push(`[DECISION]    But Rules OVERRODE AI (threat score: ${threatScore.toFixed(3)})`);
      auditLog.push(`[DECISION]    AI Factors: ${topFactors.slice(0, 3).join(', ')}`);
      
      aiDisagreement = {
        aiWanted: aiRecommendation,
        rulesChose: ruleBasedAction,
        reason: `AI detected higher threat (${threatScore.toFixed(2)}) but Rules are authority`
      };
    } else if (aiWantedLower) {
      auditLog.push(`[DECISION] 📊 AI wanted to DE-ESCALATE: ${ruleBasedAction} → ${aiRecommendation}`);
      auditLog.push(`[DECISION]    But Rules MAINTAINED decision (Rules are stricter)`);
      
      aiDisagreement = {
        aiWanted: aiRecommendation,
        rulesChose: ruleBasedAction,
        reason: `Rules enforce stricter policy than AI suggested`
      };
    }
  }

  auditLog.push(`[DECISION] 🎯 Final Action: ${finalAction} (Rules authority)`);
  auditLog.push(`[DECISION] 📊 AI Contribution: ${aiContribution}`);
  
  const finalConfidence = calculateConfidenceV3(
    aiContribution,
    threatScore,
    confidence
  );
  
  auditLog.push(`[DECISION] 💯 Confidence: ${finalConfidence.toFixed(2)}`);
  auditLog.push('[DECISION] ========================================');

  await logDecision(identityId, {
    action: finalAction,
    source: 'rules_with_ai_insight',
    ruleBasedAction,
    aiRecommendation,
    aiAgreed: aiContribution === 'agreed',
    aiDisagreement,
    threatScore,
    topFactors,
    confidence: finalConfidence
  });

  auditLog.forEach(log => console.log(log));

  return {
    action: finalAction,
    reason: buildReasonV3(finalAction, aiContribution, topFactors),
    confidence: finalConfidence,
    aiContribution,
    auditLog,
    aiDisagreement
  };
}

function calculateConfidenceV3(
  aiContribution: 'agreed' | 'noted' | 'ignored',
  threatScore: number,
  aiConfidence: string
): number {
  if (aiContribution === 'agreed') {
    return aiConfidence === 'high' ? 0.95 : 0.85;
  }
  if (aiContribution === 'noted') {
    return 0.75;
  }
  return 0.70;
}

function buildReasonV3(
  action: DefensiveAction,
  aiContribution: string,
  topFactors: string[]
): string {
  const reasons: { [key: string]: string } = {
    'ALLOW': 'No significant threats detected by rules',
    'REGENERATE': 'Rules triggered proactive regeneration',
    'LIE': 'Rules confirmed attack pattern - returning deceptive data',
    'KILL': 'Rules determined critical threat - identity destroyed'
  };

  let reason = reasons[action] || 'Security policy enforcement by rules';

  if (aiContribution === 'agreed' && topFactors.length > 0) {
    reason += ` (AI confirmed: ${topFactors.slice(0, 2).join(', ')})`;
  } else if (aiContribution === 'noted' && topFactors.length > 0) {
    reason += ` (AI noted: ${topFactors.slice(0, 2).join(', ')})`;
  }

  return reason;
}

async function logDecision(identityId: string, decision: any): Promise<void> {
  try {
    const logKey = `decision:${identityId}:${Date.now()}`;
    await db.set(logKey, JSON.stringify({
      ...decision,
      timestamp: Date.now()
    }), 86400);
  } catch (error) {
    console.error('[DECISION] Failed to log decision:', error);
  }
}

/**
 * DEPRECATED - Mantido para compatibilidade
 */
export function combineDecisions(
  ruleBasedAction: DefensiveAction,
  aiRecommendation: 'ALLOW' | 'REGENERATE' | 'LIE' | 'KILL' | null,
  validationSuccessful: boolean = false
): DefensiveAction {
  console.warn('[DECISION] ⚠️ Using deprecated combineDecisions - upgrade to combineDecisionsV3');
  return ruleBasedAction;
}

export const combineDecisionsV2 = combineDecisionsV3;