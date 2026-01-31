/**
 * Railway AI Client
 * Chama o modelo ML (Isolation Forest) rodando no Railway
 */

const AI_SERVICE_URL = process.env.AI_SERVICE_URL || 'https://rekuway-idn-mvp-production.up.railway.app';

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

export async function analyzeWithRailwayAI(features: RailwayAIFeatures): Promise<RailwayAIResponse | null> {
  try {
    console.log('[RAILWAY_AI] 🚂 Calling Railway AI Service...');
    console.log('[RAILWAY_AI] URL:', AI_SERVICE_URL);
    
    const response = await fetch(`${AI_SERVICE_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ features })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('[RAILWAY_AI] ❌ Error:', response.status, errorText);
      return null;
    }

    const data = await response.json() as RailwayAIResponse;
    console.log('[RAILWAY_AI] ✅ Threat Score:', data.threatScore);
    console.log('[RAILWAY_AI] 🎯 Recommended:', data.recommendedAction);
    console.log('[RAILWAY_AI] ⏱️  Inference:', data.inferenceTimeMs, 'ms');
    
    return data;
  } catch (error) {
    console.error('[RAILWAY_AI] ❌ Failed:', error);
    return null;
  }
}

export function convertToRailwayFeatures(aiFeatures: any): RailwayAIFeatures {
  return {
    attempt_interval_ms: aiFeatures.timeSinceLastAttempt * 1000 || 0,
    attempt_count: aiFeatures.currentAttempts || 0,
    total_attempts: aiFeatures.totalAttempts || 0,
    regenerations: aiFeatures.regenerationCount || 0,
    attempts_after_regenerate: aiFeatures.attemptsAfterRegenerate || 0,
    ip_rotation_count: aiFeatures.uniqueIPs || 0,
    fingerprint_reuse: aiFeatures.fingerprintChange ? 1 : 0,
    geolocation_change: aiFeatures.geolocationChange ? 1 : 0,
    time_deviation: aiFeatures.timeSinceLastAttempt < 5 ? 1 : 0
  };
}