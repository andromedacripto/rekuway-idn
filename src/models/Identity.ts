/**
 * Identity Model
 *
 * Representa uma identidade temporária com sistema de defesa ativo
 */
export interface Identity {
  id: string;
  userId?: string;
  publicKey: string;
  privateKeyHash: string;
  privateKey?: string;
  createdAt: number;
  expiresAt: number;
  paranoiaLevel: 'low' | 'medium' | 'high' | 'deadman';
  fakeMetadata: {
    ip: string;
    location: string;
    userAgent: string;
    device: string;
  };
  attempts: number;
  totalAttempts: number;
  regenerationCount: number;
  attemptsAfterRegenerate: number;
  lastAttemptAt: number;
  suspiciousIPs: string[];
  isAlive: boolean;
  lastHeartbeat?: number;
  lastCheckIn?: number;
  deadmanTimerSeconds?: number;
  isValidSignature?: boolean;
}

/**
 * Threat Event Types
 */
export enum ThreatEvent {
  NONE = 'none',
  BRUTE_FORCE = 'brute_force',
  SCRAPING = 'scraping',
  SUSPICIOUS_TIMING = 'suspicious_timing',
  FINGERPRINT_MATCH = 'fingerprint_match',
  RATE_LIMIT = 'rate_limit',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
  INVALID_KEY = 'invalid_key',
  DEADMAN_TIMEOUT = 'deadman_timeout'
}

/**
 * Defensive Actions
 *
 * Sistema de defesa em camadas:
 * ALLOW → REGENERATE → LIE → KILL
 */
export enum DefensiveAction {
  ALLOW = 'ALLOWED',
  LIE = 'LIE',
  REGENERATE = 'REGENERATE',
  KILL = 'KILL'
}

/**
 * Resultado da análise defensiva
 */
export interface DefensiveResponse {
  action: DefensiveAction;
  reason: string;
  identity?: Identity;
  fakeData?: Record<string, unknown>;
  newIdentity?: {
    id: string;
    publicKey: string;
    privateKey: string;
    paranoiaLevel: string;
    expiresAt: number;
  };
}

/**
 * Configuração de nível de paranoia
 */
export interface ParanoiaConfig {
  maxAttempts: number;
  regenerateThreshold: number;
  killThreshold: number;
  ttl: number;
  fakeFingerprintEnabled: boolean;
  deadmanTimer?: number;
  description?: string;
}