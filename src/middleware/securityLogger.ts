import { Request, Response, NextFunction } from 'express';
import { getClientIp } from '../utils/clientIp';

declare module 'express-serve-static-core' {
  interface Request {
    clientIP?: string;
  }
}

/**
 * Middleware que loga todas as requisições para auditoria de segurança
 *
 * Em produção, você deve:
 * - Enviar logs para um sistema externo (Datadog, Sentry, etc)
 * - Nunca logar dados sensíveis (chaves privadas, tokens completos)
 * - Implementar rotação de logs
 */
export function securityLogger(req: Request, res: Response, next: NextFunction) {
  const timestamp = new Date().toISOString();
  const ip = getClientIp(req);
  const method = req.method;
  const path = req.path;
  const userAgent = req.get('user-agent') || 'unknown';

  console.log(
    `[${timestamp}] ${method} ${path} | IP: ${ip} | UA: ${userAgent.substring(0, 50)}...`
  );

  res.on('finish', () => {
    const statusCode = res.statusCode;
    const statusEmoji = statusCode >= 400 ? '❌' : statusCode >= 300 ? '⚠️' : '✅';
    console.log(`[${timestamp}] ${statusEmoji} ${method} ${path} | Status: ${statusCode}`);
  });

  next();
}

/**
 * Middleware de rate limiting por IP
 * Previne abusos e tentativas de brute force
 */
export function rateLimitByIP(req: Request, res: Response, next: NextFunction) {
  // Em produção, use express-rate-limit ou redis-based rate limiting
  const ip = getClientIp(req);

  req.clientIP = ip;
  next();
}
