/**
 * AI Client Service — REKUWAY IDN
 *
 * FUNÇÃO 1: Análise de risco em tempo real
 * FUNÇÃO 2: Detecção de ameaças comportamentais
 * FUNÇÃO 3: Governança automatizada (read-only)
 *
 * PRINCÍPIOS INVIOLÁVEIS:
 * - IA observa, não decide
 * - IA não pode gerar falso positivo em validação bem-sucedida
 * - IA não pode alterar estado
 * - Toda saída é explicável e auditável
 * - Logs NUNCA contêm privateKey, apiKey ou secrets
 */

import {
  AIFeatures,
  AIRiskAnalysis,
  ThreatPattern,
  AIAnalysisResult,
  GovernanceRecommendation,
} from './ai-risk-types';
import { db } from '../config/database';
import { safeLog, safeError } from '../utils/sanitize';

const AI_CONFIG = {
  enabled: true,
  modelVersion: '1.0.0-rule-based',
  thresholds: {
    threatScoreHigh: 0.7,
    threatScoreCritical: 0.9,
    confidenceMinimum: 0.5,
  },
  weights: {
    attemptFrequency: 0.25,
    ipRotation: 0.2,
    geolocationChange: 0.15,
    fingerprintInconsistency: 0.15,
    postRegenerationPattern: 0.15,
    timeDeviation: 0.1,
  },
};

export async function analyzeWithAI(features: AIFeatures): Promise<AIAnalysisResult | null> {
  if (!AI_CONFIG.enabled) {
    safeLog('[AI] Disabled — skipping analysis');
    return null;
  }

  const startTime = Date.now();

  try {
    // ✅ SEGURO: loga apenas o identityId (truncado), nunca dados sensíveis
    safeLog(`[AI] 🤖 Starting analysis:`, { id: features.identityId });

    const riskAnalysis = await performRiskAnalysis(features);
    const threatPattern = await detectThreatPattern(features);
    const governance = await generateGovernance(features, riskAnalysis, threatPattern);

    const processingTimeMs = Date.now() - startTime;

    // ✅ SEGURO: métricas de análise sem dados sensíveis
    safeLog(`[AI] 📊 Risk Analysis:`, {
      id: features.identityId,
      threatScore: riskAnalysis.threatScore.toFixed(3),
      confidence: riskAnalysis.confidence,
      recommendedAction: riskAnalysis.recommendedAction || 'N/A',
      topFactors: riskAnalysis.topFactors,
      threatPattern: threatPattern.pattern,
      threatSeverity: threatPattern.severity,
      processingTimeMs,
    });

    const result: AIAnalysisResult = {
      riskAnalysis,
      threatPattern,
      governance,
      processingTimeMs,
      wasUsedInDecision: false,
    };

    await logAIAnalysis(features, result);
    return result;
  } catch (error) {
    // ✅ SEGURO: sanitize já cuida de não expor secrets no error
    safeError('[AI] ❌ Analysis failed:', error);
    return null;
  }
}

async function performRiskAnalysis(features: AIFeatures): Promise<AIRiskAnalysis> {
  const factors: { [key: string]: number } = {};
  const topFactors: string[] = [];

  factors.attemptFrequency = calculateAttemptFrequencyScore(features);
  factors.ipRotation = calculateIPRotationScore(features);
  factors.geolocationChange = features.geolocationChange ? 0.8 : 0.0;
  factors.fingerprintInconsistency = features.fingerprintChange ? 0.7 : 0.0;
  factors.postRegenerationPattern = calculatePostRegenerationScore(features);
  factors.timeDeviation = calculateTimeDeviationScore(features);

  const weightedScores = Object.entries(factors).map(([key, value]) => ({
    key,
    value,
    weighted: value * AI_CONFIG.weights[key as keyof typeof AI_CONFIG.weights],
  }));

  const threatScore = weightedScores.reduce((sum, item) => sum + item.weighted, 0);

  const sortedFactors = weightedScores
    .filter((item) => item.value > 0.3)
    .sort((a, b) => b.value - a.value)
    .slice(0, 5);

  sortedFactors.forEach((item) => topFactors.push(formatFactorName(item.key, item.value)));

  let confidence: 'low' | 'medium' | 'high' = 'low';
  if (sortedFactors.length >= 3 && threatScore > 0.6) confidence = 'high';
  else if (sortedFactors.length >= 2 || threatScore > 0.4) confidence = 'medium';

  let recommendedAction: 'ALLOW' | 'REGENERATE' | 'LIE' | 'KILL' = 'ALLOW';

  if (threatScore >= AI_CONFIG.thresholds.threatScoreCritical && confidence === 'high') {
    recommendedAction = 'KILL';
  } else if (threatScore >= AI_CONFIG.thresholds.threatScoreHigh) {
    if (features.isPostRegeneration && features.attemptsAfterRegenerate >= 1) {
      recommendedAction = 'LIE';
    } else if (features.currentAttempts > 2) {
      recommendedAction = 'REGENERATE';
    }
  }

  return {
    threatScore: Math.min(threatScore, 1.0),
    confidence,
    topFactors,
    recommendedAction,
    analysisTimestamp: Date.now(),
    modelVersion: AI_CONFIG.modelVersion,
    detailedFactors: {
      attemptFrequency: factors.attemptFrequency,
      ipRotation: factors.ipRotation,
      geolocationChange: factors.geolocationChange,
      fingerprintInconsistency: factors.fingerprintInconsistency,
      postRegenerationPattern: factors.postRegenerationPattern,
      timeDeviation: factors.timeDeviation,
    },
  };
}

async function detectThreatPattern(features: AIFeatures): Promise<ThreatPattern> {
  const evidence: string[] = [];
  let pattern: ThreatPattern['pattern'] = 'none';
  let confidence = 0.0;
  let severity: ThreatPattern['severity'] = 'low';

  if (features.isPostRegeneration && features.attemptsAfterRegenerate >= 2) {
    pattern = 'post_regeneration';
    confidence = 0.95;
    severity = 'critical';
    evidence.push(`${features.attemptsAfterRegenerate} attempts after regeneration`);
    evidence.push('Identity already regenerated once');
  } else if (features.attemptFrequency > 10 && features.ageMinutes < 5) {
    pattern = 'brute_force';
    confidence = 0.9;
    severity = 'high';
    evidence.push(`${features.attemptFrequency.toFixed(1)} attempts/minute`);
    evidence.push(
      `${features.totalAttempts} total attempts in ${features.ageMinutes.toFixed(1)} minutes`
    );
  } else if (features.ipRotationRate > 0.5 && features.uniqueIPs >= 3) {
    pattern = 'credential_stuffing';
    confidence = 0.85;
    severity = 'high';
    evidence.push(`${features.uniqueIPs} unique IPs`);
    evidence.push(`IP rotation rate: ${features.ipRotationRate.toFixed(2)}/min`);
  } else if (
    features.attemptFrequency < 0.5 &&
    features.totalAttempts > 5 &&
    features.ageMinutes > 30
  ) {
    pattern = 'low_and_slow';
    confidence = 0.7;
    severity = 'medium';
    evidence.push('Slow, distributed attempts');
    evidence.push(
      `${features.totalAttempts} attempts over ${features.ageMinutes.toFixed(1)} minutes`
    );
  } else if (features.currentAttempts >= 3 && features.timeSinceLastAttempt < 10) {
    pattern = 'brute_force';
    confidence = 0.75;
    severity = 'medium';
    evidence.push(`${features.currentAttempts} rapid attempts`);
    evidence.push('Short time between attempts');
  }

  if (features.fingerprintChange) evidence.push('Fingerprint changed');
  if (features.geolocationChange) evidence.push('Geolocation changed');

  return { pattern, confidence, evidence, severity };
}

async function generateGovernance(
  features: AIFeatures,
  riskAnalysis: AIRiskAnalysis,
  threatPattern: ThreatPattern
): Promise<GovernanceRecommendation | undefined> {
  if (riskAnalysis.threatScore < 0.7 || threatPattern.severity === 'low') return undefined;

  if (features.paranoiaLevel === 'low' && riskAnalysis.threatScore > 0.8) {
    return {
      type: 'paranoia_level_increase',
      recommendation: {
        paranoiaLevel: 'high',
        reason: `High threat score (${riskAnalysis.threatScore.toFixed(2)}) on LOW paranoia identity`,
        confidence: 'high',
        supportingData: {
          attackCount: features.totalAttempts,
          lastAttackTimestamp: Date.now(),
          patternDetected: threatPattern.pattern,
        },
      },
      suggestedAction: 'Consider upgrading paranoia level to HIGH for better protection',
      priority: 'high',
    };
  }

  if (features.isPostRegeneration && threatPattern.pattern === 'post_regeneration') {
    return {
      type: 'identity_at_risk',
      recommendation: {
        reason: 'Persistent attacks after regeneration detected',
        confidence: 'high',
        supportingData: {
          attackCount: features.attemptsAfterRegenerate,
          patternDetected: 'post_regeneration',
          affectedIdentities: [features.identityId],
        },
      },
      suggestedAction: 'Identity under coordinated attack — consider KILL or manual review',
      priority: 'urgent',
    };
  }

  return undefined;
}

function calculateAttemptFrequencyScore(features: AIFeatures): number {
  if (features.attemptFrequency > 20) return 1.0;
  if (features.attemptFrequency > 10) return 0.9;
  if (features.attemptFrequency > 5) return 0.7;
  if (features.attemptFrequency > 2) return 0.5;
  if (features.attemptFrequency > 1) return 0.3;
  return 0.0;
}

function calculateIPRotationScore(features: AIFeatures): number {
  if (features.uniqueIPs <= 1) return 0.0;
  if (features.ipRotationRate > 1.0) return 1.0;
  if (features.ipRotationRate > 0.5) return 0.8;
  if (features.ipRotationRate > 0.2) return 0.6;
  if (features.uniqueIPs >= 3) return 0.5;
  return 0.3;
}

function calculatePostRegenerationScore(features: AIFeatures): number {
  if (!features.isPostRegeneration) return 0.0;
  if (features.attemptsAfterRegenerate >= 2) return 1.0;
  if (features.attemptsAfterRegenerate === 1) return 0.8;
  return 0.4;
}

function calculateTimeDeviationScore(features: AIFeatures): number {
  if (features.timeSinceLastAttempt < 5) return 0.9;
  if (features.timeSinceLastAttempt < 15) return 0.6;
  if (features.timeSinceLastAttempt < 60) return 0.3;
  return 0.0;
}

function formatFactorName(key: string, value: number): string {
  const names: { [key: string]: string } = {
    attemptFrequency: 'High attempt frequency',
    ipRotation: 'IP rotation detected',
    geolocationChange: 'Geolocation change',
    fingerprintInconsistency: 'Fingerprint change',
    postRegenerationPattern: 'Post-regeneration attack',
    timeDeviation: 'Rapid successive attempts',
  };
  return `${names[key] || key} (${value.toFixed(2)})`;
}

async function logAIAnalysis(features: AIFeatures, result: AIAnalysisResult): Promise<void> {
  try {
    const logKey = `ai-log:${features.identityId}:${Date.now()}`;

    // ✅ SEGURO: o objeto 'features' não contém privateKey.
    // Salva para auditoria interna apenas.
    const log = {
      timestamp: Date.now(),
      identityId: features.identityId,
      features,
      result,
    };
    await db.set(logKey, JSON.stringify(log), 86400);
  } catch (error) {
    safeError('[AI] Failed to log analysis:', error);
  }
}
