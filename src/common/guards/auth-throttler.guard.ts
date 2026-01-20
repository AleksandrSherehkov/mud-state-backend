import { Injectable } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';

import { hashId } from 'src/common/helpers/log-sanitize';

type BodyWithEmail = { email?: unknown };

type ReqLike = Record<string, unknown> & {
  ip?: unknown;
  path?: unknown;
  url?: unknown;
  originalUrl?: unknown;
  method?: unknown;
  body?: unknown;
  headers?: unknown;
  socket?: unknown;
  connection?: unknown;
};

function firstNonEmptyString(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined;
  const s = v.trim();
  return s || undefined;
}

function getHeader(req: ReqLike, name: string): unknown {
  const headers = req.headers;
  if (!headers || typeof headers !== 'object') return undefined;

  const h = headers as Record<string, unknown>;
  return h[name] ?? h[name.toLowerCase()];
}

function getPath(req: ReqLike): string {
  const raw =
    (typeof req.path === 'string' && req.path) ||
    (typeof req.originalUrl === 'string' && req.originalUrl) ||
    (typeof req.url === 'string' && req.url) ||
    '';

  const q = raw.indexOf('?');
  return q >= 0 ? raw.slice(0, q) : raw;
}

function getIpFromReqIp(req: ReqLike): string | undefined {
  return firstNonEmptyString(req.ip);
}

function getIpFromXForwardedFor(req: ReqLike): string | undefined {
  const xff = getHeader(req, 'x-forwarded-for');
  const raw = firstNonEmptyString(xff);
  if (!raw) return undefined;

  const first = raw.split(',')[0];
  return firstNonEmptyString(first);
}

function getIpFromSocket(req: ReqLike): string | undefined {
  const sock = req.socket;
  if (!sock || typeof sock !== 'object') return undefined;

  const remote = (sock as { remoteAddress?: unknown }).remoteAddress;
  return firstNonEmptyString(remote);
}

function getIpFromConnection(req: ReqLike): string | undefined {
  const conn = req.connection;
  if (!conn || typeof conn !== 'object') return undefined;

  const remote = (conn as { remoteAddress?: unknown }).remoteAddress;
  return firstNonEmptyString(remote);
}

function getIp(req: ReqLike): string {
  return (
    getIpFromReqIp(req) ??
    getIpFromXForwardedFor(req) ??
    getIpFromSocket(req) ??
    getIpFromConnection(req) ??
    'unknown'
  );
}

function normalizeMethod(req: ReqLike): string {
  return typeof req.method === 'string' ? req.method.trim().toUpperCase() : '';
}

function getEmailHash(req: ReqLike): string | undefined {
  const body = req.body;
  if (!body || typeof body !== 'object') return undefined;

  const rawEmail = (body as BodyWithEmail).email;
  const email =
    typeof rawEmail === 'string' ? rawEmail.trim().toLowerCase() : '';
  return email ? hashId(email) : undefined;
}

function isPostAndEndsWith(req: ReqLike, suffix: string): boolean {
  const method = normalizeMethod(req);
  if (method !== 'POST') return false;

  const path = getPath(req);
  return path.endsWith(suffix);
}

@Injectable()
export class AuthThrottlerGuard extends ThrottlerGuard {
  protected async getTracker(req: Record<string, any>): Promise<string> {
    await Promise.resolve();

    const r = req as ReqLike;

    const ip = getIp(r);

    const isLogin = isPostAndEndsWith(r, '/auth/login');
    const isRegister = isPostAndEndsWith(r, '/auth/register');
    const isRefresh = isPostAndEndsWith(r, '/auth/refresh');

    if (isLogin || isRegister) {
      const emailHash = getEmailHash(r) ?? 'noemail';
      return `${ip}:${emailHash}`;
    }

    if (isRefresh) {
      return ip;
    }

    return ip;
  }
}
