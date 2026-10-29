import dotenv from 'dotenv';
dotenv.config();

import { Redis } from '@upstash/redis';

/**
 * Cliente Redis (Upstash REST) compartilhado por rate limit e limitadores.
 * O banco de identidades continua em config/database.ts.
 */
export const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
});
