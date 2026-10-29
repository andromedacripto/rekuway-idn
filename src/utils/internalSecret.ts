import crypto from 'crypto';

/**
 * Comparação de segredos em tempo constante.
 *
 * Os dois valores passam por SHA-256 antes de timingSafeEqual: isso
 * iguala o tamanho dos buffers (timingSafeEqual lança exceção quando
 * diferem) e evita vazar o comprimento do segredo esperado.
 */
export function safeEqualSecret(provided: unknown, expected: string | undefined): boolean {
  // Fail-closed: segredo esperado ausente/vazio nunca autoriza ninguém.
  if (typeof expected !== 'string' || expected.length === 0) return false;
  // Cabeçalhos repetidos chegam como array; só aceitamos um valor string.
  if (typeof provided !== 'string' || provided.length === 0) return false;

  const a = crypto.createHash('sha256').update(provided, 'utf8').digest();
  const b = crypto.createHash('sha256').update(expected, 'utf8').digest();
  return crypto.timingSafeEqual(a, b);
}

/**
 * Valida o cabeçalho `x-internal-secret` contra process.env.INTERNAL_SECRET.
 * Se INTERNAL_SECRET não estiver configurado, TODA requisição é recusada.
 *
 * `expected` existe apenas para testes; em produção use o padrão (env).
 */
export function validateInternalSecret(
  provided: unknown,
  expected: string | undefined = process.env.INTERNAL_SECRET
): boolean {
  return safeEqualSecret(provided, expected);
}

/**
 * Compara duas strings em tempo constante (ex.: hashes hex).
 * Diferente de safeEqualSecret, aceita esperado vazio apenas se ambos forem vazios.
 */
export function safeEqualString(a: string, b: string): boolean {
  const ha = crypto.createHash('sha256').update(a, 'utf8').digest();
  const hb = crypto.createHash('sha256').update(b, 'utf8').digest();
  return crypto.timingSafeEqual(ha, hb);
}
