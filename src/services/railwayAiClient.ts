/**
 * Railway AI Client — REKUWAY IDN
 * Logs sanitizados: NUNCA expõe privateKey, apiKey ou secrets.
 *
 * ── CONTRATO DE FEATURES (fonte única: ai-service/features.py) ──────────
 * O modelo (Isolation Forest) foi treinado com 9 features. O cliente envia
 * exatamente estas chaves em `{ "features": { ... } }`:
 *
 *   attempt_interval_ms      ms desde a última tentativa
 *   attempt_count            falhas consecutivas da identidade atual
 *   total_attempts           falhas acumuladas (sobrevive à regeneração)
 *   regenerations            quantas vezes a identidade foi regenerada
 *   ip_change                1 se mais de um IP foi visto, senão 0
 *   fingerprint_reuse        1 se o MESMO User-Agent apareceu em mais de um IP
 *                            (ataque distribuído com o mesmo fingerprint, como no treino)
 *   user_agent_entropy       entropia de Shannon do User-Agent / 8 bits, em [0,1]
 *   endpoint_sequence_score  1.0 até 3 chamadas recentes; cai 0.1 por chamada
 *                            extra (mínimo 0.2). Heurística inicial, NÃO calibrada
 *   hour_of_day              hora UTC (0-23)
 *
 * Chaves desconhecidas são ignoradas pelo serviço; ausentes valem 0.
 * Qualquer mudança aqui exige mudar features.py (e retreinar) juntos.
 *
 * A IA é CONSULTIVA: a resposta alimenta combineDecisionsV3, que mantém a
 * decisão nas regras. Sem URL/token, erro ou timeout → retorna null e o
 * sistema segue só com as regras.
 */

import { safeLog, safeError } from '../utils/sanitize';
import { AIFeatures } from './ai-risk-types';

export type RailwayAction = 'ALLOW' | 'REGENERATE' | 'LIE' | 'KILL';

const VALID_ACTIONS: readonly RailwayAction[] = ['ALLOW', 'REGENERATE', 'LIE', 'KILL'];

/** Sem default: a URL do serviço de IA deve ser configurada explicitamente. */
const AI_SERVICE_URL = process.env.AI_SERVICE_URL;
const AI_SERVICE_TOKEN = process.env.AI_SERVICE_TOKEN;
const AI_TIMEOUT_MS =
  Number(process.env.AI_SERVICE_TIMEOUT_MS) > 0 ? Number(process.env.AI_SERVICE_TIMEOUT_MS) : 3000;

export interface RailwayAIFeatures {
  attempt_interval_ms: number;
  attempt_count: number;
  total_attempts: number;
  regenerations: number;
  ip_change: number;
  fingerprint_reuse: number;
  user_agent_entropy: number;
  endpoint_sequence_score: number;
  hour_of_day: number;
}

export interface RailwayAIResponse {
  threatScore: number;
  confidence: string;
  recommendedAction: RailwayAction;
  topFactors: string[];
  inferenceTimeMs: number;
  explanation: {
    base_score: number;
    boosters_applied: unknown[];
    final_score: number;
    reasoning: string;
  };
}

/** Entropia de Shannon (bits/char) do User-Agent, normalizada por 8 bits. */
export function userAgentEntropy(userAgent: string): number {
  if (!userAgent) return 0;
  const counts = new Map<string, number>();
  for (const ch of userAgent) counts.set(ch, (counts.get(ch) || 0) + 1);
  const len = Array.from(userAgent).length;
  let bits = 0;
  counts.forEach((n) => {
    const p = n / len;
    bits -= p * Math.log2(p);
  });
  return Math.min(1, bits / 8);
}

export function endpointSequenceScore(sequence: string[]): number {
  const extra = Math.max(0, (sequence?.length || 0) - 3);
  return Math.max(0.2, 1 - extra * 0.1);
}

export function convertToRailwayFeatures(aiFeatures: AIFeatures): RailwayAIFeatures {
  return {
    attempt_interval_ms: (aiFeatures.timeSinceLastAttempt || 0) * 1000,
    attempt_count: aiFeatures.currentAttempts || 0,
    total_attempts: aiFeatures.totalAttempts || 0,
    regenerations: aiFeatures.regenerationCount || 0,
    ip_change: (aiFeatures.uniqueIPs || 0) > 1 ? 1 : 0,
    fingerprint_reuse: (aiFeatures.uniqueIPs || 0) > 1 && !aiFeatures.fingerprintChange ? 1 : 0,
    user_agent_entropy: userAgentEntropy(aiFeatures.userAgent || ''),
    endpoint_sequence_score: endpointSequenceScore(aiFeatures.endpointSequence || []),
    hour_of_day: new Date().getUTCHours(),
  };
}

function parseResponse(data: unknown): RailwayAIResponse | null {
  if (!data || typeof data !== 'object') return null;
  const d = data as Partial<RailwayAIResponse>;
  if (typeof d.threatScore !== 'number' || !Number.isFinite(d.threatScore)) return null;
  if (!VALID_ACTIONS.includes(d.recommendedAction as RailwayAction)) return null;
  return {
    ...(d as RailwayAIResponse),
    topFactors: Array.isArray(d.topFactors) ? d.topFactors.map(String) : [],
    confidence: typeof d.confidence === 'string' ? d.confidence : 'low',
  };
}

export async function analyzeWithRailwayAI(
  features: RailwayAIFeatures
): Promise<RailwayAIResponse | null> {
  if (!AI_SERVICE_URL || !AI_SERVICE_TOKEN) {
    safeLog('[RAILWAY_AI] AI_SERVICE_URL/AI_SERVICE_TOKEN not configured — rules only');
    return null;
  }

  try {
    const startTime = Date.now();

    const response = await fetch(`${AI_SERVICE_URL}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-ai-service-token': AI_SERVICE_TOKEN,
      },
      body: JSON.stringify({ features }),
      signal: AbortSignal.timeout(AI_TIMEOUT_MS),
    });

    const elapsed = Date.now() - startTime;

    if (!response.ok) {
      safeError('[RAILWAY_AI] ❌ Error:', { status: response.status, elapsedMs: elapsed });
      return null;
    }

    const data = parseResponse(await response.json());
    if (!data) {
      safeError('[RAILWAY_AI] ❌ Invalid response shape', { elapsedMs: elapsed });
      return null;
    }

    safeLog('[RAILWAY_AI] ✅ Analysis complete:', {
      threatScore: data.threatScore,
      recommendedAction: data.recommendedAction,
      inferenceTimeMs: data.inferenceTimeMs,
      totalTimeMs: elapsed,
      topFactors: data.topFactors.slice(0, 3),
    });

    return data;
  } catch (error) {
    safeError('[RAILWAY_AI] ❌ Failed:', error);
    return null;
  }
}
