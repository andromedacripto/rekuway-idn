import { safeError } from '../utils/sanitize';

/**
 * Notifica o dashboard (fire-and-forget). Nunca lança e nunca inclui segredos
 * no corpo; o segredo interno vai só no header.
 */
function withExternalRef<T extends { metadata?: Record<string, unknown>; externalRef?: string }>(
  event: T
) {
  const { externalRef, ...rest } = event;
  return externalRef ? { ...rest, metadata: { ...(rest.metadata ?? {}), externalRef } } : rest;
}

export function notifyDashboard(event: {
  userId?: string;
  type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  blocked: boolean;
  ipAddress?: string;
  metadata?: Record<string, unknown>;
  /** Código da pessoa dona da identidade; vai dentro de metadata. */
  externalRef?: string;
}): void {
  const dashUrl = process.env.DASHBOARD_URL || 'https://rekuway-dashboard.vercel.app';
  fetch(`${dashUrl}/api/keys/event`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-internal-secret': process.env.INTERNAL_SECRET || '',
    },
    body: JSON.stringify(withExternalRef(event)),
    signal: AbortSignal.timeout(3000),
  }).catch((error) => safeError('[DASHBOARD] event failed', error));
}
