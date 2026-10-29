import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import identityRoutes from './routes/identityRoutes';
import internalRoutes from './routes/internalRoutes';
import verifyIdentityRouter from './routes/verify-identity';
import apiKeyRoutes from './routes/apiKeyRoutes';
import { requireApiKey } from './middleware/auth';
import analyzeRoutes from './routes/analyzeRoutes';
import { getClientIp } from './utils/clientIp';
import { redis } from './config/redis';
import { safeError } from './utils/sanitize';

dotenv.config();

const app = express();

// ── Remove fingerprint do Express ─────────────────────────────
app.disable('x-powered-by');

// ── Middleware global de headers ──────────────────────────────
app.use((req: Request, res: Response, next: NextFunction) => {
  res.removeHeader('x-powered-by');
  res.removeHeader('server');
  res.removeHeader('x-vercel-id');
  res.setHeader('server', 'edge');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// ── CORS: somente origens explícitas (ALLOWED_ORIGINS, separadas por vírgula) ──
// Sem ALLOWED_ORIGINS, nenhuma origem de navegador é liberada. Chamadas
// servidor-a-servidor (sem cabeçalho Origin) não dependem de CORS.
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => callback(null, !!origin && allowedOrigins.includes(origin)),
  })
);

// ── Rate Limiting Global por IP (Redis) ──────────────────────
const _RL_MAX = 10;
const _RL_WIN = 60;

// Rotas sensíveis: se o Redis falhar, a requisição é recusada (fail-closed).
// Vale para /identity/check, /identity/new, /api-keys e qualquer método que
// altere estado. Só leitura (GET/HEAD/OPTIONS) segue em fail-open.
// O caminho é normalizado porque o roteador do Express ignora maiúsculas e "/" final.
function isFailClosedRoute(req: Request): boolean {
  const path = req.path.toLowerCase().replace(/\/+$/, '');
  if (path === '/identity/check' || path === '/identity/new') return true;
  if (path === '/api-keys' || path.startsWith('/api-keys/')) return true;
  return !['GET', 'HEAD', 'OPTIONS'].includes(req.method);
}

app.use(async (req: Request, res: Response, next: NextFunction) => {
  try {
    // IP definido pelo proxy confiável (X-Real-IP). Ver src/utils/clientIp.ts.
    const ip = getClientIp(req);
    const key = `rl:${ip}`;
    // INCR + EXPIRE NX em uma transação: a janela sempre recebe TTL, mesmo
    // se a conexão cair no meio (evita bloqueio permanente de um IP).
    const [count] = await redis
      .multi()
      .incr(key)
      .expire(key, _RL_WIN, 'NX')
      .exec<[number, number]>();
    if (count > _RL_MAX) {
      const excess = count - _RL_MAX;
      const penaltyMs = Math.min(excess * 200, 3000);
      await new Promise((r) => setTimeout(r, penaltyMs));
      return res.status(200).json({ success: true, status: 'ok', mode: 'stealth' });
    }
    next();
  } catch (error) {
    if (isFailClosedRoute(req)) {
      safeError('[RATE_LIMIT] Redis indisponível — fail-closed', error);
      return res.status(200).json({ success: true, status: 'ok', mode: 'stealth' });
    }
    next();
  }
});

app.use(express.json({ limit: '16kb' }));

// ── Health check ──────────────────────────────────────────────
app.get('/', (req: Request, res: Response) => {
  res.json({ status: 'ok', ts: Date.now() });
});

app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', ts: Date.now() });
});

// ── Routes ────────────────────────────────────────────────────
app.use('/api-keys', apiKeyRoutes);
app.use('/identity', identityRoutes);
app.use('/internal', internalRoutes);
app.use('/analyze', analyzeRoutes);
app.use('/api/verify-identity', requireApiKey, verifyIdentityRouter);

// ── Catch-all para métodos não permitidos ─────────────────────
app.use((req: Request, res: Response) => {
  res.status(200).json({ success: true, status: 'ok', mode: 'stealth' });
});

// ── Erros (JSON malformado, corpo grande demais): resposta uniforme ──
app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
  safeError('[APP] Request error', err);
  res.status(200).json({ success: true, status: 'ok', mode: 'stealth' });
});

export default app;
