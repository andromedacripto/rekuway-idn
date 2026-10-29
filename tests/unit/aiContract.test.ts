import { readFileSync } from 'fs';
import { join } from 'path';
import { describe, expect, it } from 'vitest';
import { AIFeatures } from '../../src/services/ai-risk-types';
import {
  convertToRailwayFeatures,
  endpointSequenceScore,
  userAgentEntropy,
} from '../../src/services/railwayAiClient';

const features = (over: Partial<AIFeatures> = {}): AIFeatures =>
  ({
    identityId: 'x',
    paranoiaLevel: 'high',
    currentAttempts: 2,
    totalAttempts: 4,
    regenerationCount: 1,
    timeSinceLastAttempt: 1.5,
    uniqueIPs: 2,
    fingerprintChange: true,
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64)',
    endpointSequence: ['check', 'check'],
    ...over,
  }) as AIFeatures;

describe('contrato de features TS <-> ai-service', () => {
  it('as chaves enviadas são exatamente as 9 de features.py (feature_order)', () => {
    const py = readFileSync(join(__dirname, '../../ai-service/features.py'), 'utf8');
    const block = py.slice(py.indexOf('feature_order = ['));
    const order = [...block.slice(0, block.indexOf(']')).matchAll(/'([a-z_]+)'/g)].map((m) => m[1]);
    expect(order).toHaveLength(9);
    expect(Object.keys(convertToRailwayFeatures(features())).sort()).toEqual([...order].sort());
  });

  it('converte valores no formato esperado', () => {
    const f = convertToRailwayFeatures(features());
    expect(f).toMatchObject({
      attempt_interval_ms: 1500,
      attempt_count: 2,
      total_attempts: 4,
      regenerations: 1,
      ip_change: 1,
      fingerprint_reuse: 0, // UA mudou: não é o mesmo fingerprint
    });
    expect(
      convertToRailwayFeatures(features({ fingerprintChange: false, uniqueIPs: 3 }))
    ).toMatchObject({ ip_change: 1, fingerprint_reuse: 1 });
    expect(
      convertToRailwayFeatures(features({ fingerprintChange: false, uniqueIPs: 1 }))
    ).toMatchObject({ ip_change: 0, fingerprint_reuse: 0 });
    expect(f.hour_of_day).toBeGreaterThanOrEqual(0);
    expect(f.hour_of_day).toBeLessThanOrEqual(23);
  });

  it('entropia do User-Agent fica em [0,1] e vazio vale 0', () => {
    expect(userAgentEntropy('')).toBe(0);
    const e = userAgentEntropy('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
    expect(e).toBeGreaterThan(0);
    expect(e).toBeLessThanOrEqual(1);
  });

  it('score de sequência cai com chamadas extras e tem piso de 0.2', () => {
    expect(endpointSequenceScore(['check'])).toBe(1);
    expect(endpointSequenceScore(new Array(20).fill('check'))).toBe(0.2);
  });
});
