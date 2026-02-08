import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request, Response as ExpressResponse } from 'express';
import type { CookieOptions } from 'express-serve-static-core';
import { randomUUID } from 'node:crypto';
import * as ms from 'ms';

type CookieSameSite = 'lax' | 'strict' | 'none';

@Injectable()
export class AuthCookieService {
  private readonly apiPrefix: string;
  private readonly appEnv: string;

  constructor(private readonly config: ConfigService) {
    this.apiPrefix = this.config.get<string>('API_PREFIX', 'api');
    this.appEnv = this.config.get<string>('APP_ENV', 'development');
  }

  private apiPath(): string {
    return `/${this.apiPrefix}`;
  }

  private isProd(): boolean {
    return this.appEnv === 'production';
  }

  private isRequestSecure(req: Request): boolean {
    if (req.secure) return true;
    const xfProto = req.header('x-forwarded-proto');
    return xfProto?.toLowerCase() === 'https';
  }

  private cookieSameSite(): CookieSameSite {
    const raw = (
      this.config.get<string>('COOKIE_SAMESITE') ?? ''
    ).toLowerCase();
    if (raw === 'lax' || raw === 'strict' || raw === 'none') return raw;
    return 'lax';
  }

  private isCrossSiteCookiesEnabled(): boolean {
    return (
      String(this.config.get('COOKIE_CROSS_SITE') ?? '')
        .toLowerCase()
        .trim() === 'true'
    );
  }

  private tryParseMs(raw: string): number | undefined {
    const value = ms(raw as ms.StringValue);
    return typeof value === 'number' && Number.isFinite(value)
      ? value
      : undefined;
  }

  private refreshCookieMaxAgeMs(): number {
    const raw = this.config.get<string>('JWT_REFRESH_EXPIRES_IN') ?? '7d';
    return this.tryParseMs(raw) ?? 7 * 24 * 60 * 60 * 1000;
  }

  refreshCookieOptions(req: Request): CookieOptions {
    const maxAge = this.refreshCookieMaxAgeMs();
    const secure = this.isProd() ? true : this.isRequestSecure(req);

    let sameSite: CookieSameSite = this.cookieSameSite();

    if (
      this.isProd() &&
      sameSite === 'none' &&
      !this.isCrossSiteCookiesEnabled()
    ) {
      sameSite = 'lax';
    }

    if (sameSite === 'none' && !secure) {
      throw new Error(
        'Cookie misconfiguration: SameSite=None requires Secure (HTTPS). Check TLS termination / proxy / BASE_URL.',
      );
    }

    return {
      httpOnly: true,
      secure,
      sameSite,
      path: this.apiPath(),
      signed: true,
      maxAge,
      expires: new Date(Date.now() + maxAge),
    };
  }

  csrfCookieOptions(req: Request): CookieOptions {
    const secure = this.isProd() ? true : this.isRequestSecure(req);

    let sameSite: CookieSameSite = this.cookieSameSite();

    if (
      this.isProd() &&
      sameSite === 'none' &&
      !this.isCrossSiteCookiesEnabled()
    ) {
      sameSite = 'lax';
    }

    if (sameSite === 'none' && !secure) {
      throw new Error(
        'Cookie misconfiguration: SameSite=None requires Secure (HTTPS). Check TLS termination / proxy.',
      );
    }

    return {
      httpOnly: false,
      secure,
      sameSite,
      path: this.apiPath(),
      maxAge: 15 * 60 * 1000,
    };
  }

  setCsrfCookie(res: ExpressResponse, req: Request): string {
    const csrfToken = randomUUID();
    res.cookie('csrfToken', csrfToken, this.csrfCookieOptions(req));
    return csrfToken;
  }

  setRefreshCookie(
    res: ExpressResponse,
    req: Request,
    refreshToken: string,
  ): void {
    res.cookie('refreshToken', refreshToken, this.refreshCookieOptions(req));
  }

  setAuthCookies(
    res: ExpressResponse,
    req: Request,
    refreshToken: string,
  ): void {
    this.setRefreshCookie(res, req, refreshToken);
    this.setCsrfCookie(res, req);
  }

  clearAuthCookies(res: ExpressResponse, req: Request): void {
    res.clearCookie('refreshToken', this.refreshCookieClearOptions(req));
    res.clearCookie('csrfToken', this.csrfCookieClearOptions(req));
  }

  private stripExpiry(opts: CookieOptions): CookieOptions {
    const { maxAge: _maxAge, expires: _expires, ...rest } = opts;
    return rest;
  }

  private refreshCookieClearOptions(req: Request): CookieOptions {
    return this.stripExpiry(this.refreshCookieOptions(req));
  }

  private csrfCookieClearOptions(req: Request): CookieOptions {
    return this.stripExpiry(this.csrfCookieOptions(req));
  }
}
