import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import identityRoutes from './routes/identityRoutes';
import { startDeadmanMonitor } from './services/defensiveService';

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Health check
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Rekuway IDN API is running ✅',
    version: '1.0.0-MVP',
    features: [
      'Hybrid Defense (ALLOW → REGENERATE → LIE → KILL)',
      'Deadman Switch with Heartbeat Monitor 💓',
      '4 Paranoia Levels',
      'Fake Metadata Deception'
    ]
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Routes
app.use('/identity', identityRoutes);

// 🔥 CRÍTICO: Iniciar Deadman Monitor ao iniciar servidor
startDeadmanMonitor();

// Start server (only if not in Vercel)
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`🔐 Rekuway IDN API running on port ${PORT}`);
    console.log(`💓 Deadman Monitor active`);
  });
}

export default app;