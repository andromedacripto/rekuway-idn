import net from 'net';
import { Request } from 'express';

/**
 * IP do cliente a partir do proxy confiável.
 *
 * Decisão: usamos `X-Real-IP`, NUNCA o primeiro valor de `X-Forwarded-For`.
 *
 * - Vercel (https://vercel.com/docs/headers/request-headers): o edge
 *   sobrescreve `X-Forwarded-For` e não repassa IPs externos; `X-Real-IP`
 *   é idêntico a ele (um único IP, o do cliente).
 * - Railway (https://docs.railway.com/networking/public-networking/specs-and-limits):
 *   o edge define `X-Real-IP` com o IP remoto do cliente e substitui
 *   (não anexa) qualquer cópia enviada pelo chamador. A Railway recomenda
 *   `X-Real-IP` e diz que `X-Forwarded-For` não tem número fixo de entradas.
 *
 * Limite da garantia: só vale para tráfego que entrou pelo edge público
 * (Vercel / domínio público da Railway). Chamadas diretas ao processo, via
 * rede privada (*.railway.internal) ou TCP proxy não são sanitizadas, e em
 * desenvolvimento local o cabeçalho é forjável. Sem `X-Real-IP` válido,
 * caímos no endereço do socket (nunca em `X-Forwarded-For`).
 */
export function getClientIp(req: Pick<Request, 'headers' | 'socket'>): string {
  const raw = req.headers['x-real-ip'];
  const candidate = (Array.isArray(raw) ? raw[0] : raw)?.trim();
  if (candidate && net.isIP(candidate) !== 0) return candidate;

  const socketIp = req.socket?.remoteAddress;
  if (socketIp && net.isIP(socketIp) !== 0) return socketIp;

  return 'unknown';
}
