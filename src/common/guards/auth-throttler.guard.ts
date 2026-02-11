import { Injectable } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import { normalizeIp } from 'src/common/helpers/ip-normalize';
import { hashId } from 'src/common/helpers/log-sanitize';
import { createHash } from 'node:crypto';

type BodyWithEmail = { email?: unknown };

type ReqLike = Record<string, unknown> & {
  ip?: unknown;
  path?: unknown;
  url?: unknown;
  originalUrl?: unknown;
  method?: unknown;
  body?: unknown;
  socket?: unknown;
  connection?: unknown;
  cookies?: Record<string, unknown>;
  signedCookies?: Record<string, unknown>;
};

function firstNonEmptyString(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined;
  const s = v.trim();
  return s || undefined;
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
  const raw =
    getIpFromReqIp(req) ??
    getIpFromSocket(req) ??
    getIpFromConnection(req) ??
    'unknown';

  return normalizeIp(raw);
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

type AuthedUser = { userId?: unknown };

function getUserIdFromReq(req: Record<string, unknown>): string | undefined {
  const u = (req as { user?: AuthedUser }).user;
  const raw = u?.userId;
  return typeof raw === 'string' && raw.trim() ? raw.trim() : undefined;
}

function isPathContains(req: ReqLike, segment: string): boolean {
  const path = getPath(req);
  return path.includes(segment);
}

function getHeaderString(req: ReqLike, name: string): string {
  const headersUnknown = (req as { headers?: unknown }).headers;

  if (!headersUnknown || typeof headersUnknown !== 'object') return '';

  const headers = headersUnknown as Record<string, unknown>;
  const raw = headers[name.toLowerCase()];

  if (typeof raw === 'string') return raw;
  if (Array.isArray(raw) && typeof raw[0] === 'string') return raw[0];

  return '';
}

function getUserAgent(req: ReqLike): string {
  const ua = getHeaderString(req, 'user-agent').trim();
  return ua ? ua.slice(0, 255) : '';
}

function getSignedCookie(req: ReqLike, name: string): string | undefined {
  const signedRaw = req.signedCookies?.[name];

  if (signedRaw === false) return undefined;
  return typeof signedRaw === 'string' ? signedRaw : undefined;
}

function sha256hex(input: string, slice = 16): string {
  return createHash('sha256')
    .update(input, 'utf8')
    .digest('hex')
    .slice(0, slice);
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
      const ua = getUserAgent(r);
      const uaHash = ua ? hashId(ua) : 'noua';

      const refreshCookie = getSignedCookie(r, 'refreshToken');
      const cookieKey = refreshCookie
        ? sha256hex(refreshCookie, 16)
        : 'nocookie';

      return `${ip}:${uaHash}:${cookieKey}`;
    }

    const userId = getUserIdFromReq(req);
    const isSessions = isPathContains(r, '/sessions');
    const isLogout = isPostAndEndsWith(r, '/auth/logout');
    const isMe = getPath(r).endsWith('/auth/me');

    if (userId && (isSessions || isLogout || isMe)) {
      return `${ip}:${userId}`;
    }

    return ip;
  }
}
