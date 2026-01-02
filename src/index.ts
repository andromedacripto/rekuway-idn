import express from 'express';
import dotenv from 'dotenv';
import identityRoutes from './routes/identityRoutes';
import { securityLogger, rateLimitByIP } from './middleware/securityLogger';
import { startDeadmanMonitor } from './services/defensiveService';

// Carrega variáveis de ambiente
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares globais
app.use(express.json());
app.use(securityLogger);
app.use(rateLimitByIP);

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Rekuway IDN',
    version: '1.0.0-MVP',
    timestamp: new Date().toISOString()
  });
});

// Rotas da API
app.use('/identity', identityRoutes);

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
  `);

  // Inicia monitor de deadman switches
  startDeadmanMonitor();
});

export default app;