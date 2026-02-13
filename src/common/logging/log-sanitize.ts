import * as crypto from 'node:crypto';
import { normalizeIp } from '../net/ip-normalize';

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
  'tokenhash',
  'refresh_token',
  'refreshtoken',
  'accesstoken',
  'access_token',
];

const JWT_LIKE = /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g;
const BEARER_LIKE = /Bearer\s+[A-Za-z0-9._-]+/gi;

// eslint-disable-next-line no-control-regex
const ASCII_CONTROL_CHARS = /[\x00-\x1F\x7F]/g;

export function maskIp(raw?: string | null): string {
  const ip = normalizeIp(raw ?? '');
  const parts = ip.split('.');
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.0`;
  return ip;
}

export function normalizeUserAgent(ua: unknown): string {
  const raw =
    typeof ua === 'string'
      ? ua
      : Array.isArray(ua)
        ? typeof ua[0] === 'string'
          ? ua[0]
          : ''
        : '';

  if (!raw) return '';

  const cleaned = raw
    .replaceAll(ASCII_CONTROL_CHARS, ' ')
    .replaceAll(/\s+/g, ' ')
    .trim();

  if (!cleaned) return '';

  return cleaned.length > MAX_UA ? cleaned.slice(0, MAX_UA) : cleaned;
}

export function hashId(value: string, len = 12): string {
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, len);
}

export function sanitizeString(input: string): string {
  const noCtl = input.replaceAll(ASCII_CONTROL_CHARS, ' ');
  return noCtl
    .replaceAll(JWT_LIKE, '[REDACTED_JWT]')
    .replaceAll(BEARER_LIKE, 'Bearer [REDACTED]')
    .replaceAll(/\s+/g, ' ')
    .trim();
}

function isUnknownArray(v: unknown): v is unknown[] {
  return Array.isArray(v);
}

export function sanitizeMeta<T>(value: T): T;
export function sanitizeMeta(value: unknown): unknown;

export function sanitizeMeta(value: unknown): unknown {
  if (value === null || value === undefined) return value;

  if (typeof value === 'string') return sanitizeString(value);
  if (typeof value === 'number' || typeof value === 'boolean') return value;

  if (isUnknownArray(value)) return value.map((v) => sanitizeMeta(v));

  if (typeof value !== 'object') return value;

  const obj = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};

  for (const [k, v] of Object.entries(obj)) {
    out[k] = isSensitiveKey(k) ? redactSensitiveValue(v) : sanitizeMeta(v);
  }

  return out;
}

function isSensitiveKey(key: string): boolean {
  const lk = key.toLowerCase();
  return SENSITIVE_KEY_SUBSTRINGS.some((s) => lk.includes(s));
}

function redactSensitiveValue(v: unknown): unknown {
  if (typeof v === 'number' || typeof v === 'boolean') return v;
  return '[REDACTED]';
}
