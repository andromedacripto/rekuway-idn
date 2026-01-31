/**
 * Identity Model
 * 
 * Representa uma identidade temporária com sistema de defesa ativo
 */

export interface Identity {
  id: string;
  publicKey: string;
  privateKeyHash: string;
  privateKey?: string; // Só existe na criação
  createdAt: number;
  expiresAt: number;
  paranoiaLevel: 'low' | 'medium' | 'high' | 'deadman';
  
  // Metadados falsos para fingerprinting
  fakeMetadata: {
    ip: string;
    location: string;
    userAgent: string;
    device: string;
  };
  
  // Sistema defensivo HÍBRIDO
  attempts: number;                    // Tentativas na identidade atual
  totalAttempts: number;               // Tentativas totais (NUNCA reseta) 🔥
  regenerationCount: number;           // Quantas vezes regenerou 🔥
  attemptsAfterRegenerate: number;     // Tentativas após última regeneração 🔥
  
  lastAttemptAt: number;
  suspiciousIPs: string[];
  isAlive: boolean;
  
  // Deadman switch (só para paranoiaLevel = 'deadman')
  lastHeartbeat?: number;              // Última confirmação de vida 🔥
  lastCheckIn?: number;                // Alias para lastHeartbeat
  deadmanTimerSeconds?: number;
  
  // ✅ ADICIONADO: Flag de validação criptográfica
  // Retornado por validateIdentity() para indicar se a chave estava correta
  isValidSignature?: boolean;
}

/**
 * Threat Event Types
 */
export enum ThreatEvent {
  NONE = 'none',
  BRUTE_FORCE = 'brute_force',                   // 🔥 Múltiplas tentativas
  SCRAPING = 'scraping',                         // 🔥 Comportamento de bot
  SUSPICIOUS_TIMING = 'suspicious_timing',
  FINGERPRINT_MATCH = 'fingerprint_match',
  RATE_LIMIT = 'rate_limit',                     // 🔥 Taxa anormal
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',   // Alias
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
  ALLOW = 'ALLOWED',           // ⚠️ Registra tentativa
  LIE = 'LIE',                 // 🎭 Retorna dados falsos
  REGENERATE = 'REGENERATE',   // 🔄 Cria nova identidade
  KILL = 'KILL'                // 💀 Destruição permanente
}

/**
 * Resultado da análise defensiva
 */
export interface DefensiveResponse {
  action: DefensiveAction;
  reason: string;
  identity?: Identity;
  fakeData?: any;
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
  maxAttempts: number;              // Limite absoluto para KILL
  regenerateThreshold: number;      // Quando regenerar
  killThreshold: number;            // (deprecated, usar maxAttempts)
  ttl: number;                      // ✅ CORRIGIDO: ttl ao invés de ttlSeconds
  fakeFingerprintEnabled: boolean;
  deadmanTimer?: number;            // ✅ ADICIONADO: opcional
  description?: string;
}