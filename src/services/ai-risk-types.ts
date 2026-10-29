/**
 * AI Risk Analysis Types
 *
 * Contratos imutáveis para IA defensiva observadora.
 * A IA NUNCA executa ações, apenas fornece insights.
 */

export interface AIRiskAnalysis {
  threatScore: number;
  confidence: 'low' | 'medium' | 'high';
  topFactors: string[];
  recommendedAction?: 'ALLOW' | 'REGENERATE' | 'LIE' | 'KILL';
  analysisTimestamp: number;
  modelVersion: string;
  detailedFactors?: {
    attemptFrequency: number;
    ipRotation: number;
    geolocationChange: number;
    fingerprintInconsistency: number;
    postRegenerationPattern: number;
    timeDeviation: number;
  };
}

export interface ThreatPattern {
  pattern:
    | 'brute_force'
    | 'credential_stuffing'
    | 'replay_attack'
    | 'low_and_slow'
    | 'post_regeneration'
    | 'enumeration'
    | 'none';
  confidence: number;
  evidence: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface GovernanceRecommendation {
  type:
    | 'paranoia_level_increase'
    | 'identity_at_risk'
    | 'client_anomaly'
    | 'deadman_suggested'
    | 'policy_adjustment';
  recommendation: {
    paranoiaLevel?: 'low' | 'medium' | 'high' | 'deadman';
    reason: string;
    confidence: 'low' | 'medium' | 'high';
    supportingData?: {
      attackCount?: number;
      lastAttackTimestamp?: number;
      patternDetected?: string;
      affectedIdentities?: string[];
    };
  };
  suggestedAction: string;
  priority: 'low' | 'medium' | 'high' | 'urgent';
}

export interface AIFeatures {
  identityId: string;
  paranoiaLevel: string;
  ageMinutes: number;
  currentAttempts: number;
  totalAttempts: number;
  regenerationCount: number;
  attemptsAfterRegenerate: number;
  timeSinceLastAttempt: number;
  timeSinceCreation: number;
  attemptFrequency: number;
  clientIP: string;
  uniqueIPs: number;
  ipRotationRate: number;
  userAgent: string;
  fingerprintChange: boolean;
  geolocationChange: boolean;
  isPostRegeneration: boolean;
  isNearMaxAttempts: boolean;
  endpointSequence: string[];
  checkToHeartbeatRatio: number;
}

export interface AIAnalysisResult {
  riskAnalysis: AIRiskAnalysis;
  threatPattern: ThreatPattern;
  governance?: GovernanceRecommendation;
  processingTimeMs: number;
  wasUsedInDecision: boolean;
}

export interface AIAnalysisLog {
  timestamp: number;
  identityId: string;
  features: AIFeatures;
  result: AIAnalysisResult;
  finalDecision?: {
    action: string;
    wasAIFollowed: boolean;
    overrideReason?: string;
  };
}

export interface AIConfig {
  enabled: boolean;
  thresholds: {
    threatScoreHigh: number;
    threatScoreCritical: number;
    confidenceMinimum: number;
  };
  weights: {
    attemptFrequency: number;
    ipRotation: number;
    geolocationChange: number;
    fingerprintInconsistency: number;
    postRegenerationPattern: number;
    timeDeviation: number;
  };
  model: {
    version: string;
    endpoint?: string;
  };
}
