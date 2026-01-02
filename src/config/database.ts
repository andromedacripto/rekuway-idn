import { Identity } from '../models/Identity';

/**
 * Simulação de KV Store usando Map in-memory
 * Em produção, substituir por Redis, Cloudflare KV ou Supabase
 * 
 * Estrutura:
 * - identities: Map<id, Identity>
 * - ipTracking: Map<ip, {attempts, lastAttempt}>
 */

class InMemoryKVStore {
  private identities: Map<string, Identity> = new Map();
  private ipTracking: Map<string, { attempts: number; lastAttempt: number }> = new Map();

  /**
   * Salva uma identidade no store
   */
  async setIdentity(id: string, identity: Identity): Promise<void> {
    this.identities.set(id, identity);
  }

  /**
   * Busca uma identidade por ID
   */
  async getIdentity(id: string): Promise<Identity | null> {
    return this.identities.get(id) || null;
  }

  /**
   * Deleta uma identidade (kill)
   */
  async deleteIdentity(id: string): Promise<boolean> {
    return this.identities.delete(id);
  }

  /**
   * Lista todas as identidades (útil pra debug)
   */
  async listIdentities(): Promise<Identity[]> {
    return Array.from(this.identities.values());
  }

  /**
   * Tracking de tentativas por IP
   */
  async trackIP(ip: string): Promise<number> {
    const existing = this.ipTracking.get(ip);
    const now = Date.now();

    if (existing) {
      // Reseta contador se última tentativa foi há mais de 5 minutos
      if (now - existing.lastAttempt > 300000) {
        this.ipTracking.set(ip, { attempts: 1, lastAttempt: now });
        return 1;
      }
      
      existing.attempts++;
      existing.lastAttempt = now;
      this.ipTracking.set(ip, existing);
      return existing.attempts;
    }

    this.ipTracking.set(ip, { attempts: 1, lastAttempt: now });
    return 1;
  }

  /**
   * Limpa tracking de um IP
   */
  async clearIPTracking(ip: string): Promise<void> {
    this.ipTracking.delete(ip);
  }

  /**
   * Limpa identidades expiradas (garbage collector)
   */
  async cleanExpired(): Promise<number> {
    const now = Date.now();
    let cleaned = 0;

    for (const [id, identity] of this.identities.entries()) {
      if (identity.expiresAt < now || !identity.isAlive) {
        this.identities.delete(id);
        cleaned++;
      }
    }

    return cleaned;
  }
}

// Singleton instance
export const db = new InMemoryKVStore();

// Auto-cleanup a cada 5 minutos
setInterval(() => {
  db.cleanExpired().then(count => {
    if (count > 0) {
      console.log(`[DB] Cleaned ${count} expired identities`);
    }
  });
}, 300000);