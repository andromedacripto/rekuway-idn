import { z } from 'zod';

// ─────────────────────────────────────────────
//  POST /identity/new
// ─────────────────────────────────────────────
export const newIdentitySchema = z.object({
  paranoiaLevel: z.enum(['low', 'medium', 'high', 'deadman']).default('medium'),
});

// ─────────────────────────────────────────────
//  POST /identity/check
// ─────────────────────────────────────────────
export const checkIdentitySchema = z.object({
  token:      z.string().length(64).regex(/^[0-9a-f]+$/).optional(),
  identityId: z.string().uuid().optional(),
  privateKey: z.string().min(1).optional(),
}).refine(
  (data) => data.token || (data.identityId && data.privateKey),
  { message: 'Provide either token or identityId + privateKey' }
);

// ─────────────────────────────────────────────
//  POST /identity/heartbeat
// ─────────────────────────────────────────────
export const heartbeatSchema = z.object({
  identityId: z.string().uuid(),
  privateKey: z.string().min(1),
});

// ─────────────────────────────────────────────
//  POST /identity/regenerate
// ─────────────────────────────────────────────
export const regenerateSchema = z.object({
  identityId: z.string().uuid(),
  privateKey: z.string().min(1),
});

// ─────────────────────────────────────────────
//  POST /identity/kill
// ─────────────────────────────────────────────
export const killSchema = z.object({
  identityId: z.string().uuid(),
  privateKey: z.string().min(1),
});

// ─────────────────────────────────────────────
//  Helper — parse e retorna erro padronizado
// ─────────────────────────────────────────────
export function parseBody<T>(
  schema: z.ZodSchema<T>,
  body: unknown
): { success: true; data: T } | { success: false; error: string } {
  const result = schema.safeParse(body);
  if (!result.success) {
    const msg = result.error.issues.map(e => `${e.path.join('.')}: ${e.message}`).join(', ');
    return { success: false, error: msg };
  }
  return { success: true, data: result.data };
}