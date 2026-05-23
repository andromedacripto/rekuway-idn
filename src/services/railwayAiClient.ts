/**
 * Railway AI Client — REKUWAY IDN
 * Logs sanitizados: NUNCA expõe privateKey, apiKey ou secrets.
 */

import { safeLog, safeError } from '../utils/sanitize';
import { AIFeatures } from './ai-risk-types';

const AI_SERVICE_URL =
  process.env.AI_SERVICE_URL || 'https://rekuway-idn-mvp-production.up.railway.app';

export interface RailwayAIFeatures {
  attempt_interval_ms: number;
  attempt_count: number;
  total_attempts: number;
  regenerations: number;
  attempts_after_regenerate: number;
  ip_rotation_count: number;
  fingerprint_reuse: number;
  geolocation_change: number;
  time_deviation: number;
  failure_rate: number;
  consecutive_failures: number;
  velocity_score: number;
  avg_time_between_attempts: number;
  is_rapid_fire: number;
  brute_force_score: number;
  suspicious_pattern_score: number;
  time_to_first_failure: number;
  has_repeated_failures: number;
  escalation_rate: number;
}

export interface RailwayAIResponse {
  threatScore: number;
  confidence: string;
  recommendedAction: string;
  topFactors: string[];
  inferenceTimeMs: number;
  explanation: {
    base_score: number;
    boosters_applied: string[];
    final_score: number;
    reasoning: string;
  };
}

export function convertToRailwayFeatures(aiFeatures: AIFeatures): RailwayAIFeatures {
  const timeSinceLastMs    = (aiFeatures.timeSinceLastAttempt || 0) * 1000;
  const currentAttempts    = aiFeatures.currentAttempts   || 0;
  const totalAttempts      = aiFeatures.totalAttempts     || 0;
  const regenerations      = aiFeatures.regenerationCount || 0;
  const attemptsAfterRegen = aiFeatures.attemptsAfterRegenerate || 0;

  const failureRate         = totalAttempts > 0 ? currentAttempts / totalAttempts : 0;
  const consecutiveFailures = currentAttempts;

  let velocityScore = 0.1;
  if      (timeSinceLastMs < 2000)  velocityScore = 1.0;
  else if (timeSinceLastMs < 5000)  velocityScore = 0.7;
  else if (timeSinceLastMs < 10000) velocityScore = 0.4;

  const avgTimeBetween = totalAttempts > 1
    ? timeSinceLastMs / Math.max(1, currentAttempts)
    : timeSinceLastMs;

  const isRapidFire = timeSinceLastMs < 5000 ? 1 : 0;

  const bruteForceScore = Math.min(1.0, (
    (currentAttempts / 10) * 0.4 +
    velocityScore * 0.3 +
    failureRate * 0.3
  ));

  const hasIPRotation        = (aiFeatures.uniqueIPs || 0) > 1;
  const hasFingerprintChange = aiFeatures.fingerprintChange ? 1 : 0;
  const hasGeoChange         = aiFeatures.geolocationChange ? 1 : 0;

  const suspiciousPatternScore = (
    bruteForceScore * 0.4 +
    (hasIPRotation ? 0.3 : 0) +
    (hasFingerprintChange * 0.15) +
    (hasGeoChange * 0.15)
  );

  const timeToFirstFailure  = currentAttempts === 1 ? timeSinceLastMs : 0;
  const hasRepeatedFailures = currentAttempts >= 2 ? 1 : 0;
  const escalationRate      = attemptsAfterRegen > 0 ? Math.min(1.0, attemptsAfterRegen / 5) : 0;

  return {
    attempt_interval_ms:       timeSinceLastMs,
    attempt_count:             currentAttempts,
    total_attempts:            totalAttempts,
    regenerations,
    attempts_after_regenerate: attemptsAfterRegen,
    ip_rotation_count:         aiFeatures.uniqueIPs || 0,
    fingerprint_reuse:         hasFingerprintChange,
    geolocation_change:        hasGeoChange ? 1 : 0,
    time_deviation:            timeSinceLastMs < 5000 ? 1 : 0,
    failure_rate:              failureRate,
    consecutive_failures:      consecutiveFailures,
    velocity_score:            velocityScore,
    avg_time_between_attempts: avgTimeBetween,
    is_rapid_fire:             isRapidFire,
    brute_force_score:         bruteForceScore,
    suspicious_pattern_score:  suspiciousPatternScore,
    time_to_first_failure:     timeToFirstFailure,
    has_repeated_failures:     hasRepeatedFailures,
    escalation_rate:           escalationRate,
  };
}

export async function analyzeWithRailwayAI(
  features: RailwayAIFeatures
): Promise<RailwayAIResponse | null> {
  try {
    safeLog('[RAILWAY_AI] 🚂 Calling Railway AI Service...', {
      attempts:        features.attempt_count,
      failureRate:     features.failure_rate.toFixed(2),
      velocityScore:   features.velocity_score.toFixed(2),
      bruteForceScore: features.brute_force_score.toFixed(2),
      suspiciousScore: features.suspicious_pattern_score.toFixed(2),
    });

    const startTime = Date.now();

    const response = await fetch(`${AI_SERVICE_URL}/analyze`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ features }),
      signal:  AbortSignal.timeout(10000),
    });

    const elapsed = Date.now() - startTime;

    if (!response.ok) {
      safeError('[RAILWAY_AI] ❌ Error:', { status: response.status, elapsedMs: elapsed });
      return null;
    }

    const data = (await response.json()) as RailwayAIResponse;

    safeLog('[RAILWAY_AI] ✅ Analysis complete:', {
      threatScore:       data.threatScore,
      recommendedAction: data.recommendedAction,
      inferenceTimeMs:   data.inferenceTimeMs,
      totalTimeMs:       elapsed,
      topFactors:        data.topFactors?.slice(0, 3),
    });

    return data;
  } catch (error) {
    safeError('[RAILWAY_AI] ❌ Failed:', error);
    return null;
  }
}