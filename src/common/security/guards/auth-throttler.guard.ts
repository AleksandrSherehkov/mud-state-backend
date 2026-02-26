import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ThrottlerException,
  ThrottlerGuard,
  type ThrottlerRequest,
} from '@nestjs/throttler';

import { normalizeIp } from 'src/common/net/ip-normalize';
import { hashId } from 'src/common/logging/log-sanitize';
import { createHash } from 'node:crypto';

import { THROTTLE_AUTH_SECONDARY } from 'src/common/throttle/config/throttle-env';

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
  headers?: Record<string, unknown>;
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

function isPost(req: ReqLike): boolean {
  return normalizeMethod(req) === 'POST';
}

function isPostAndEndsWith(req: ReqLike, suffix: string): boolean {
  if (!isPost(req)) return false;
  return getPath(req).endsWith(suffix);
}

function isPostAndStartsWithAuth(req: ReqLike): boolean {
  if (!isPost(req)) return false;
  return getPath(req).includes('/auth/');
}

type AuthedUser = { userId?: unknown };

function getUserIdFromReq(req: Record<string, unknown>): string | undefined {
  const u = (req as { user?: AuthedUser }).user;
  const raw = u?.userId;
  return typeof raw === 'string' && raw.trim() ? raw.trim() : undefined;
}

function isPathContains(req: ReqLike, segment: string): boolean {
  return getPath(req).includes(segment);
}

function getHeaderString(req: ReqLike, name: string): string {
  const headers = req.headers;
  if (!headers || typeof headers !== 'object') return '';

  const raw = headers[name.toLowerCase()];
  if (typeof raw === 'string') return raw;
  if (Array.isArray(raw) && typeof raw[0] === 'string') return raw[0];

  return '';
}

function getUserAgent(req: ReqLike): string {
  const ua = getHeaderString(req, 'user-agent').trim();
  return ua ? ua.slice(0, 255) : '';
}

function getUaHash(req: ReqLike): string {
  const ua = getUserAgent(req);
  return ua ? hashId(ua) : 'noua';
}

function getEmailHash(req: ReqLike): string | undefined {
  const body = req.body;
  if (!body || typeof body !== 'object') return undefined;

  const rawEmail = (body as BodyWithEmail).email;
  const email =
    typeof rawEmail === 'string' ? rawEmail.trim().toLowerCase() : '';
  return email ? hashId(email) : undefined;
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
  @Inject(ConfigService)
  private readonly config!: ConfigService;

  protected async getTracker(req: Record<string, any>): Promise<string> {
    await Promise.resolve();

    const r = req as ReqLike;
    const ip = getIp(r);

    const isLogin = isPostAndEndsWith(r, '/auth/login');
    const isRegister = isPostAndEndsWith(r, '/auth/register');
    const isRefresh = isPostAndEndsWith(r, '/auth/refresh');

    if (isLogin || isRegister) {
      return ip;
    }

    if (isRefresh) {
      const uaHash = getUaHash(r);

      const mode = String(
        this.config.get<string>('THROTTLE_REFRESH_TRACKER_MODE', 'ip_ua'),
      )
        .trim()
        .toLowerCase();

      if (mode === 'ip_ua') {
        return `${ip}:${uaHash}`;
      }

      const refreshCookie = getSignedCookie(r, 'refreshToken');
      if (!refreshCookie) {
        return `${ip}:${uaHash}:nocookie`;
      }

      if (mode === 'ip_ua_cookie_bucket') {
        const bucketLenRaw = Number(
          this.config.get<number>('THROTTLE_REFRESH_COOKIE_BUCKET_LEN', 2),
        );

        const bucketLen =
          Number.isFinite(bucketLenRaw) &&
          bucketLenRaw >= 1 &&
          bucketLenRaw <= 8
            ? Math.floor(bucketLenRaw)
            : 2;

        const bucket = sha256hex(refreshCookie, bucketLen);
        return `${ip}:${uaHash}:b${bucket}`;
      }

      const cookieKey = sha256hex(refreshCookie, 16);
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

  private async enforceUnauthBurst(req: Record<string, any>, r: ReqLike) {
    const userId = getUserIdFromReq(req);
    if (userId) return;
    if (!isPostAndStartsWithAuth(r)) return;

    const ip = getIp(r);

    const burst = THROTTLE_AUTH_SECONDARY.unauthBurst;

    const key = `unauth:${ip}`;

    const rec = await this.storageService.increment(
      key,
      burst.ttl,
      burst.limit,
      burst.blockDuration,
      'unauthBurst',
    );

    if (rec.isBlocked) throw new ThrottlerException();
  }

  private async enforceEmailSecondary(req: Record<string, any>, r: ReqLike) {
    const userId = getUserIdFromReq(req);
    if (userId) return;

    const isLogin = isPostAndEndsWith(r, '/auth/login');
    const isRegister = isPostAndEndsWith(r, '/auth/register');
    if (!isLogin && !isRegister) return;

    const emailHash = getEmailHash(r);
    if (!emailHash) return;

    const cfg = isLogin
      ? THROTTLE_AUTH_SECONDARY.loginEmail
      : THROTTLE_AUTH_SECONDARY.registerEmail;

    const key = `email:${emailHash}`;

    const rec = await this.storageService.increment(
      key,
      cfg.ttl,
      cfg.limit,
      cfg.blockDuration,
      isLogin ? 'loginEmail' : 'registerEmail',
    );

    if (rec.isBlocked) throw new ThrottlerException();
  }

  protected async handleRequest(
    requestProps: ThrottlerRequest,
  ): Promise<boolean> {
    const req = requestProps.context
      .switchToHttp()
      .getRequest<Record<string, any>>();

    const r = req as ReqLike;

    await this.enforceUnauthBurst(req, r);
    await this.enforceEmailSecondary(req, r);

    return super.handleRequest(requestProps);
  }
}
