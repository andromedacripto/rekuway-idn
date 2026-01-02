/**
 * Interface que define a estrutura de uma identidade temporária
 */
export interface Identity {
  id: string;                    // UUID único da identidade
  publicKey: string;             // Chave pública para validação
  privateKeyHash: string;        // Hash da chave privada (nunca expor a chave real)
  createdAt: number;             // Timestamp de criação
  expiresAt: number;             // Timestamp de expiração
  paranoiaLevel: 'low' | 'medium' | 'high' | 'deadman';
  
  // Dados falsos que podem ser retornados quando em modo "mentir"
  fakeMetadata: {
    ip: string;
    userAgent: string;
    location: string;
    device: string;
  };
  
  // Tracking de tentativas suspeitas
  attempts: number;              // Contador de tentativas de acesso
  lastAttemptAt: number;         // Timestamp da última tentativa
  suspiciousIPs: string[];       // Lista de IPs suspeitos
  
  // Deadman switch
  lastHeartbeat?: number;        // Última confirmação de atividade legítima
  isAlive: boolean;              // Status da identidade
}

/**
 * Eventos que podem ser detectados pelo sistema
 */
export enum ThreatEvent {
  BRUTE_FORCE = 'brute_force',           // Múltiplas tentativas seguidas
  SCRAPING = 'scraping',                 // Comportamento de bot
  FINGERPRINT_MATCH = 'fingerprint_match', // Mesmo fingerprint detectado
  RATE_LIMIT = 'rate_limit',             // Taxa de requisições anormal
  DEADMAN_TIMEOUT = 'deadman_timeout'    // Timeout do deadman switch
}

/**
 * Ações defensivas que o sistema pode tomar
 */
export enum DefensiveAction {
  ALLOW = 'allow',           // Permitir acesso normal
  LIE = 'lie',              // Retornar metadados falsos
  REGENERATE = 'regenerate', // Gerar nova identidade
  KILL = 'kill'             // Destruir identidade imediatamente
}