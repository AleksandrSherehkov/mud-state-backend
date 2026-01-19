import * as crypto from 'node:crypto';
import { normalizeIp } from './ip-normalize';

const MAX_UA = 255;

const SENSITIVE_KEY_SUBSTRINGS = [
  'password',
  'pass',
  'token',
  'authorization',
  'cookie',
  'set-cookie',
  'secret',
  'apikey',
  'api_key',
  'privatekey',
  'refresh',
  'access',
  'tokenhash',
  'refresh_token',
  'refreshtoken',
];

const JWT_LIKE = /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g;
const BEARER_LIKE = /Bearer\s+[A-Za-z0-9._-]+/gi;

export function maskIp(raw?: string | null): string {
  const ip = normalizeIp(raw ?? '');
  const parts = ip.split('.');
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.0`;
  return ip;
}

export function normalizeUserAgent(ua: unknown): string {
  if (typeof ua === 'string') {
    const s = ua.trim();
    return s.length > MAX_UA ? s.slice(0, MAX_UA) : s;
  }
  if (Array.isArray(ua)) return normalizeUserAgent(ua[0]);
  return '';
}

export function hashId(value: string, len = 12): string {
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, len);
}

export function sanitizeString(input: string): string {
  return input
    .replace(JWT_LIKE, '[REDACTED_JWT]')
    .replace(BEARER_LIKE, 'Bearer [REDACTED]');
}

/**
 * Глубокая санация метаданных:
 * - редакт по ключам
 * - санация строковых значений (JWT/Bearer)
 */
function isUnknownArray(v: unknown): v is unknown[] {
  return Array.isArray(v);
}

export function sanitizeMeta<T>(value: T): T;
export function sanitizeMeta(value: unknown): unknown;

export function sanitizeMeta(value: unknown): unknown {
  if (value === null || value === undefined) return value;

  if (typeof value === 'string') return sanitizeString(value);
  if (typeof value === 'number' || typeof value === 'boolean') return value;

  if (isUnknownArray(value)) {
    return value.map((v) => sanitizeMeta(v));
  }

  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};

    for (const [k, v] of Object.entries(obj)) {
      const lk = k.toLowerCase();
      const isSensitiveKey = SENSITIVE_KEY_SUBSTRINGS.some((s) =>
        lk.includes(s),
      );

      if (isSensitiveKey) {
        if (typeof v === 'number' || typeof v === 'boolean') {
          out[k] = v;
        } else {
          out[k] = '[REDACTED]';
        }
      } else {
        out[k] = sanitizeMeta(v);
      }
    }

    return out;
  }

  return value;
}
