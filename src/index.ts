// ⚠️ IMPORTANTE: dotenv DEVE ser carregado ANTES de qualquer import!
import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import identityRoutes from './routes/identityRoutes';
import apiKeyRoutes from './routes/apiKeyRoutes';
import { securityLogger, rateLimitByIP } from './middleware/securityLogger';
import { startDeadmanMonitor } from './services/defensiveService';

const app = express();
// Root endpoint for API status
app.get('/', (req, res) => {
  res.json({ success: true, message: 'Rekuway IDN API is running ✅' });
});
const PORT = process.env.PORT || 3000;

// Middlewares globais
app.use(express.json());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  credentials: true
}));
app.use(securityLogger);
app.use(rateLimitByIP);

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Rekuway IDN',
    version: '1.0.0-MVP',
    timestamp: new Date().toISOString(),
    redis: process.env.UPSTASH_REDIS_REST_URL ? 'connected' : 'not configured'
  });
});

// Rotas da API
app.use('/identity', identityRoutes);
app.use('/api-keys', apiKeyRoutes);

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found'
  });
});

// Error handler global
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('[ERROR]', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});

// Inicia servidor
app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════╗
║     🔐 REKUWAY IDN - MVP v1.0        ║
║   Identity Deadman Network           ║
╚════════════════════════════════════════╝

🚀 Server running on port ${PORT}
📡 Endpoints:
   POST   /identity/new     - Create identity
   POST   /identity/check   - Validate + defensive logic
   POST   /identity/kill    - Destroy identity
   GET    /identity/status/:id - Check status
   
🛡️  Deadman monitor: ACTIVE
⚙️  Environment: ${process.env.NODE_ENV || 'development'}
🗄️  Database: ${process.env.UPSTASH_REDIS_REST_URL ? 'Redis (Upstash)' : 'In-Memory'}
  `);

  // Inicia monitor de deadman switches
  startDeadmanMonitor();
});

export default app;
