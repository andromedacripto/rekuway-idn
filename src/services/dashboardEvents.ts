import { safeError } from '../utils/sanitize';

/**
 * Notifica o dashboard (fire-and-forget). Nunca lança e nunca inclui segredos
 * no corpo; o segredo interno vai só no header.
 */
export function notifyDashboard(event: {
  userId?: string;
  type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  blocked: boolean;
  ipAddress?: string;
  metadata?: Record<string, unknown>;
}): void {
  const dashUrl = process.env.DASHBOARD_URL || 'https://rekuway-dashboard.vercel.app';
  fetch(`${dashUrl}/api/keys/event`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-internal-secret': process.env.INTERNAL_SECRET || '',
    },
    body: JSON.stringify(event),
    signal: AbortSignal.timeout(3000),
  }).catch((error) => safeError('[DASHBOARD] event failed', error));
}
