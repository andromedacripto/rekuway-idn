/**
 * Feature Extraction Service
 *
 * Extrai features estruturadas da identidade e contexto de requisição.
 * Input padronizado para análise da IA.
 */

import { Identity } from '../models/Identity';
import { AIFeatures } from './ai-risk-types';
import { db } from '../config/database';
import paranoiaConfig from '../config/paranoia.json';

export async function extractFeatures(
  identity: Identity,
  clientIP: string,
  userAgent: string
): Promise<AIFeatures> {
  const now = Date.now();
  const ageMinutes = (now - identity.createdAt) / 60000;
  const timeSinceCreation = (now - identity.createdAt) / 1000;
  const timeSinceLastAttempt = identity.lastAttemptAt
    ? (now - identity.lastAttemptAt) / 1000
    : timeSinceCreation;

  const attemptFrequency = ageMinutes > 0
    ? identity.totalAttempts / ageMinutes
    : 0;

  const ipHistory = await getIPHistory(identity.id);
  const uniqueIPs = ipHistory.length;
  const ipRotationRate = ageMinutes > 0
    ? uniqueIPs / ageMinutes
    : 0;

  const lastFingerprint = await getLastFingerprint(identity.id);
  const fingerprintChange = lastFingerprint
    ? lastFingerprint.userAgent !== userAgent
    : false;

  const lastGeo = await getLastGeolocation(identity.id);
  const currentGeo = estimateGeolocation(clientIP);
  const geolocationChange = lastGeo
    ? lastGeo.country !== currentGeo.country
    : false;

  const isPostRegeneration = (identity.regenerationCount || 0) > 0;
  const config = paranoiaConfig[identity.paranoiaLevel];
  const maxAttempts = config.maxAttempts;
  const isNearMaxAttempts = identity.attempts >= (maxAttempts * 0.7);

  const endpointSequence = await getEndpointSequence(identity.id);
  const checkCount = endpointSequence.filter(e => e === 'check').length;
  const heartbeatCount = endpointSequence.filter(e => e === 'heartbeat').length;
  const checkToHeartbeatRatio = heartbeatCount > 0
    ? checkCount / heartbeatCount
    : checkCount;

  await trackClientIP(identity.id, clientIP);
  await trackFingerprint(identity.id, { userAgent, timestamp: now });
  await trackGeolocation(identity.id, currentGeo);

  return {
    identityId: identity.id,
    paranoiaLevel: identity.paranoiaLevel,
    ageMinutes,
    currentAttempts: identity.attempts,
    totalAttempts: identity.totalAttempts || identity.attempts,
    regenerationCount: identity.regenerationCount || 0,
    attemptsAfterRegenerate: identity.attemptsAfterRegenerate || 0,
    timeSinceLastAttempt,
    timeSinceCreation,
    attemptFrequency,
    clientIP,
    uniqueIPs,
    ipRotationRate,
    userAgent,
    fingerprintChange,
    geolocationChange,
    isPostRegeneration,
    isNearMaxAttempts,
    endpointSequence,
    checkToHeartbeatRatio
  };
}

export async function trackEndpoint(
  identityId: string,
  endpoint: string
): Promise<void> {
  try {
    const key = `endpoints:${identityId}`;
    const existing = await db.get(key);
    
    // ✅ CORRIGIDO: Validar se é JSON válido antes de parsear
    let sequence: string[] = [];
    if (existing && typeof existing === 'string') {
      try {
        if (existing.startsWith('[')) {
          sequence = JSON.parse(existing);
        }
      } catch {
        sequence = [];
      }
    }

    sequence.push(endpoint);
    if (sequence.length > 20) {
      sequence.shift();
    }

    await db.set(key, JSON.stringify(sequence), 3600);
  } catch (error) {
    console.error('[FEATURES] Failed to track endpoint:', error);
  }
}

async function getEndpointSequence(identityId: string): Promise<string[]> {
  try {
    const key = `endpoints:${identityId}`;
    const data = await db.get(key);
    
    // ✅ CORRIGIDO: Validar se é JSON válido
    if (data && typeof data === 'string' && data.startsWith('[')) {
      try {
        return JSON.parse(data);
      } catch {
        return [];
      }
    }
    return [];
  } catch (error) {
    return [];
  }
}

async function trackClientIP(identityId: string, ip: string): Promise<void> {
  try {
    const key = `ips:${identityId}`;
    const existing = await db.get(key);
    
    // ✅ CORRIGIDO: Validar se é JSON válido
    let ips: string[] = [];
    if (existing && typeof existing === 'string') {
      try {
        if (existing.startsWith('[')) {
          ips = JSON.parse(existing);
        }
      } catch {
        ips = [];
      }
    }

    if (!ips.includes(ip)) {
      ips.push(ip);
    }

    await db.set(key, JSON.stringify(ips), 3600);
  } catch (error) {
    console.error('[FEATURES] Failed to track IP:', error);
  }
}

async function getIPHistory(identityId: string): Promise<string[]> {
  try {
    const key = `ips:${identityId}`;
    const data = await db.get(key);
    
    // ✅ CORRIGIDO: Validar se é JSON válido
    if (data && typeof data === 'string' && data.startsWith('[')) {
      try {
        return JSON.parse(data);
      } catch {
        return [];
      }
    }
    return [];
  } catch (error) {
    return [];
  }
}

async function trackFingerprint(
  identityId: string,
  fingerprint: { userAgent: string; timestamp: number }
): Promise<void> {
  try {
    const key = `fingerprint:${identityId}`;
    await db.set(key, JSON.stringify(fingerprint), 3600);
  } catch (error) {
    console.error('[FEATURES] Failed to track fingerprint:', error);
  }
}

async function getLastFingerprint(
  identityId: string
): Promise<{ userAgent: string; timestamp: number } | null> {
  try {
    const key = `fingerprint:${identityId}`;
    const data = await db.get(key);
    
    // ✅ CORRIGIDO: Validar se é JSON válido
    if (data && typeof data === 'string' && data.startsWith('{')) {
      try {
        return JSON.parse(data);
      } catch {
        return null;
      }
    }
    return null;
  } catch (error) {
    return null;
  }
}

async function trackGeolocation(
  identityId: string,
  geo: { country: string; region: string }
): Promise<void> {
  try {
    const key = `geo:${identityId}`;
    await db.set(key, JSON.stringify(geo), 3600);
  } catch (error) {
    console.error('[FEATURES] Failed to track geolocation:', error);
  }
}

async function getLastGeolocation(
  identityId: string
): Promise<{ country: string; region: string } | null> {
  try {
    const key = `geo:${identityId}`;
    const data = await db.get(key);
    
    // ✅ CORRIGIDO: Validar se é JSON válido
    if (data && typeof data === 'string' && data.startsWith('{')) {
      try {
        return JSON.parse(data);
      } catch {
        return null;
      }
    }
    return null;
  } catch (error) {
    return null;
  }
}

function estimateGeolocation(ip: string): { country: string; region: string } {
  if (ip.startsWith('192.168.') || ip.startsWith('127.')) {
    return { country: 'LOCAL', region: 'LOCAL' };
  }
  if (ip.startsWith('10.')) {
    return { country: 'PRIVATE', region: 'PRIVATE' };
  }
  return { country: 'UNKNOWN', region: 'UNKNOWN' };
}