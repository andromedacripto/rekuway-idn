/**
 * Railway AI Client - Enhanced Version
 * 
 * FILOSOFIA: Railway AI é uma CONSELHEIRA, NÃO decisora.
 * - Ela OBSERVA padrões e RECOMENDA ações
 * - O SISTEMA DE REGRAS sempre tem a DECISÃO FINAL
 * - IA fornece inteligência adicional, não autonomia
 * 
 * Features melhoradas para detecção mais precisa de ataques
 */

const AI_SERVICE_URL = process.env.AI_SERVICE_URL || 'https://rekuway-idn-mvp-production.up.railway.app';

export interface RailwayAIFeatures {
  // Features existentes (compatibilidade)
  attempt_interval_ms: number;
  attempt_count: number;
  total_attempts: number;
  regenerations: number;
  attempts_after_regenerate: number;
  ip_rotation_count: number;
  fingerprint_reuse: number;
  geolocation_change: number;
  time_deviation: number;
  
  // 🔥 NOVAS FEATURES INTELIGENTES:
  failure_rate: number;              // Taxa de falhas (0-1)
  consecutive_failures: number;      // Falhas seguidas sem sucesso
  velocity_score: number;            // Velocidade de tentativas (0-1)
  avg_time_between_attempts: number; // Média de tempo entre tentativas (ms)
  is_rapid_fire: number;             // 1 se < 5s entre tentativas, 0 caso contrário
  brute_force_score: number;         // Score de padrão de força bruta (0-1)
  suspicious_pattern_score: number;  // Score de padrão suspeito geral (0-1)
  time_to_first_failure: number;     // Tempo até primeira falha (ms)
  has_repeated_failures: number;     // 1 se tem falhas repetidas, 0 caso contrário
  escalation_rate: number;           // Taxa de escalação de tentativas (0-1)
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

/**
 * Converte features do sistema para features da Railway AI
 * COM CÁLCULOS INTELIGENTES para melhor detecção
 */
export function convertToRailwayFeatures(aiFeatures: any): RailwayAIFeatures {
  // === FEATURES BÁSICAS (compatibilidade) ===
  const timeSinceLastMs = (aiFeatures.timeSinceLastAttempt || 0) * 1000;
  const currentAttempts = aiFeatures.currentAttempts || 0;
  const totalAttempts = aiFeatures.totalAttempts || 0;
  const regenerations = aiFeatures.regenerationCount || 0;
  const attemptsAfterRegen = aiFeatures.attemptsAfterRegenerate || 0;
  
  // === CÁLCULOS INTELIGENTES ===
  
  // 1. FAILURE RATE (taxa de falhas)
  // Se todas tentativas falharam = 1.0, se nenhuma = 0.0
  const failureRate = totalAttempts > 0 ? currentAttempts / totalAttempts : 0;
  
  // 2. CONSECUTIVE FAILURES (falhas seguidas)
  // Quanto mais falhas seguidas, mais suspeito
  const consecutiveFailures = currentAttempts;
  
  // 3. VELOCITY SCORE (velocidade de tentativas)
  // Quanto mais rápido, mais suspeito (0-1)
  // < 2s = 1.0 (muito suspeito)
  // 2-5s = 0.7
  // 5-10s = 0.4
  // > 10s = 0.1 (normal)
  let velocityScore = 0.1;
  if (timeSinceLastMs < 2000) velocityScore = 1.0;
  else if (timeSinceLastMs < 5000) velocityScore = 0.7;
  else if (timeSinceLastMs < 10000) velocityScore = 0.4;
  
  // 4. AVG TIME BETWEEN ATTEMPTS (média de tempo)
  // Estimativa baseada no histórico
  const avgTimeBetween = totalAttempts > 1 
    ? timeSinceLastMs / Math.max(1, currentAttempts)
    : timeSinceLastMs;
  
  // 5. IS RAPID FIRE (tentativas muito rápidas)
  const isRapidFire = timeSinceLastMs < 5000 ? 1 : 0;
  
  // 6. BRUTE FORCE SCORE (padrão de força bruta)
  // Combina: muitas tentativas + velocidade alta + taxa de falha alta
  const bruteForceScore = (
    (currentAttempts / 10) * 0.4 +      // Peso: quantidade de tentativas
    velocityScore * 0.3 +                 // Peso: velocidade
    failureRate * 0.3                     // Peso: taxa de falhas
  );
  const bruteForceScoreNormalized = Math.min(1.0, bruteForceScore);
  
  // 7. SUSPICIOUS PATTERN SCORE (padrão suspeito geral)
  // Combina múltiplos indicadores
  const hasIPRotation = (aiFeatures.uniqueIPs || 0) > 1;
  const hasFingerprintChange = aiFeatures.fingerprintChange ? 1 : 0;
  const hasGeoChange = aiFeatures.geolocationChange ? 1 : 0;
  
  const suspiciousPatternScore = (
    bruteForceScoreNormalized * 0.4 +      // Padrão de força bruta
    (hasIPRotation ? 0.3 : 0) +            // Rotação de IP
    (hasFingerprintChange * 0.15) +        // Mudança de fingerprint
    (hasGeoChange * 0.15)                  // Mudança de geolocalização
  );
  
  // 8. TIME TO FIRST FAILURE (tempo até primeira falha)
  // Se falhou rápido = suspeito (bot)
  // Se demorou = menos suspeito (humano)
  const timeToFirstFailure = currentAttempts === 1 ? timeSinceLastMs : 0;
  
  // 9. HAS REPEATED FAILURES (falhas repetidas)
  const hasRepeatedFailures = currentAttempts >= 2 ? 1 : 0;
  
  // 10. ESCALATION RATE (taxa de escalação)
  // Quanto mais rápido as tentativas aumentam, mais suspeito
  const escalationRate = attemptsAfterRegen > 0 
    ? Math.min(1.0, attemptsAfterRegen / 5)
    : 0;
  
  // === RETORNA FEATURES COMPLETAS ===
  return {
    // Features originais (compatibilidade)
    attempt_interval_ms: timeSinceLastMs,
    attempt_count: currentAttempts,
    total_attempts: totalAttempts,
    regenerations: regenerations,
    attempts_after_regenerate: attemptsAfterRegen,
    ip_rotation_count: aiFeatures.uniqueIPs || 0,
    fingerprint_reuse: hasFingerprintChange,
    geolocation_change: hasGeoChange ? 1 : 0,
    time_deviation: timeSinceLastMs < 5000 ? 1 : 0,
    
    // Novas features inteligentes
    failure_rate: failureRate,
    consecutive_failures: consecutiveFailures,
    velocity_score: velocityScore,
    avg_time_between_attempts: avgTimeBetween,
    is_rapid_fire: isRapidFire,
    brute_force_score: bruteForceScoreNormalized,
    suspicious_pattern_score: suspiciousPatternScore,
    time_to_first_failure: timeToFirstFailure,
    has_repeated_failures: hasRepeatedFailures,
    escalation_rate: escalationRate
  };
}

export async function analyzeWithRailwayAI(features: RailwayAIFeatures): Promise<RailwayAIResponse | null> {
  try {
    console.log('[RAILWAY_AI] 🚂 Calling Railway AI Service...');
    console.log('[RAILWAY_AI] 📊 Features:', {
      attempts: features.attempt_count,
      failureRate: features.failure_rate.toFixed(2),
      velocityScore: features.velocity_score.toFixed(2),
      bruteForceScore: features.brute_force_score.toFixed(2),
      suspiciousScore: features.suspicious_pattern_score.toFixed(2)
    });
    
    const startTime = Date.now();
    
    const response = await fetch(`${AI_SERVICE_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ features }),
      signal: AbortSignal.timeout(10000) // 10s timeout
    });

    const elapsed = Date.now() - startTime;

    if (!response.ok) {
      const errorText = await response.text();
      console.error('[RAILWAY_AI] ❌ Error:', response.status, errorText);
      return null;
    }

    const data = await response.json() as RailwayAIResponse;
    
    console.log('[RAILWAY_AI] ✅ Threat Score:', data.threatScore);
    console.log('[RAILWAY_AI] 🎯 Recommended:', data.recommendedAction);
    console.log('[RAILWAY_AI] ⏱️  Inference:', data.inferenceTimeMs, 'ms');
    console.log('[RAILWAY_AI] ⏱️  Total Time:', elapsed, 'ms');
    
    // 🔥 LOG IMPORTANTE: Mostrar top factors
    if (data.topFactors && data.topFactors.length > 0) {
      console.log('[RAILWAY_AI] 📈 Top Factors:', data.topFactors.slice(0, 3).join(', '));
    }
    
    return data;
  } catch (error) {
    console.error('[RAILWAY_AI] ❌ Failed:', error);
    console.error('[RAILWAY_AI] ❌ Error details:', {
      name: (error as Error).name,
      message: (error as Error).message
    });
    return null;
  }
}