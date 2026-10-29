import { redis } from '../config/redis';

/** Contador de janela fixa. Lança se o armazenamento falhar (o chamador decide). */
export interface CounterStore {
  incrWindow(key: string, windowSec: number): Promise<number>;
  peek(key: string): Promise<number>;
}

export const redisCounter: CounterStore = {
  async incrWindow(key, windowSec) {
    // INCR + EXPIRE NX numa transação: a janela sempre recebe TTL.
    const [count] = await redis
      .multi()
      .incr(key)
      .expire(key, windowSec, 'NX')
      .exec<[number, number]>();
    return count;
  },
  async peek(key) {
    return Number((await redis.get<number>(key)) ?? 0);
  },
};

/**
 * true quando a chave estourou o limite. Erro de armazenamento é tratado como
 * "estourou" (fail-closed): rotas sensíveis preferem negar a deixar passar.
 */
export async function isOverLimit(
  key: string,
  max: number,
  windowSec: number,
  store: CounterStore = redisCounter
): Promise<boolean> {
  try {
    return (await store.incrWindow(key, windowSec)) > max;
  } catch {
    return true;
  }
}

/** Lê o contador sem incrementar. Erro de armazenamento conta como bloqueado. */
export async function isBlocked(
  key: string,
  max: number,
  store: CounterStore = redisCounter
): Promise<boolean> {
  try {
    return (await store.peek(key)) >= max;
  } catch {
    return true;
  }
}

/** Registra uma falha. Erros são ignorados: o bloqueio já falha fechado na leitura. */
export async function recordFailure(
  key: string,
  windowSec: number,
  store: CounterStore = redisCounter
): Promise<void> {
  try {
    await store.incrWindow(key, windowSec);
  } catch {
    /* ignorado */
  }
}
