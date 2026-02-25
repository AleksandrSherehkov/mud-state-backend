import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from './types/jwt.types';
import type { StringValue } from 'ms';
import { AppLogger } from 'src/logger/logger.service';
import { RefreshTokenHashService } from 'src/common/security/crypto/refresh-token-hash.service';

@Injectable()
export class JwtTokenService {
  constructor(
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
    private readonly logger: AppLogger,
    private readonly refreshHash: RefreshTokenHashService,
  ) {
    this.logger.setContext(JwtTokenService.name);
  }
  private issuer() {
    return this.getRequired('JWT_ISSUER');
  }
  private audience() {
    return this.getRequired('JWT_AUDIENCE');
  }

  private getRequired(key: string): string {
    const v = this.config.get<string>(key);
    if (!v) {
      this.logger.error(
        'Missing required config value',
        undefined,
        JwtTokenService.name,
        {
          event: 'token.config.missing',
          key,
        },
      );
      throw new Error(`Missing required config: ${key}`);
    }
    return v;
  }

  private async signToken(
    payload: JwtPayload,
    secret: string,
    expiresIn: StringValue | number,
  ): Promise<string> {
    return this.jwt.signAsync(payload, {
      secret,
      expiresIn,
      issuer: this.issuer(),
      audience: this.audience(),
    });
  }
  generateRefreshTokenSalt(): string {
    return this.refreshHash.generateSaltHex();
  }

  hashRefreshToken(token: string, salt?: string | null): string {
    return this.refreshHash.hash(token, salt);
  }
  safeEqualHex(a: string, b: string): boolean {
    return this.refreshHash.safeEqualHex(a, b);
  }

  async signAccessToken(payload: JwtPayload): Promise<string> {
    const defaultAccessExpiresIn: StringValue = '10m';
    const expiresIn =
      this.config.get<StringValue>('JWT_ACCESS_EXPIRES_IN') ??
      defaultAccessExpiresIn;

    return this.signToken(
      payload,
      this.getRequired('JWT_ACCESS_SECRET'),
      expiresIn,
    );
  }

  async signRefreshToken(payload: JwtPayload): Promise<string> {
    const defaultRefreshExpiresIn: StringValue = '7d';
    const expiresIn =
      this.config.get<StringValue>('JWT_REFRESH_EXPIRES_IN') ??
      defaultRefreshExpiresIn;

    return this.signToken(
      payload,
      this.getRequired('JWT_REFRESH_SECRET'),
      expiresIn,
    );
  }

  private mapRefreshVerifyErrorToReason(
    err: unknown,
  ):
    | 'expired'
    | 'not_active_yet'
    | 'invalid_signature'
    | 'malformed'
    | 'invalid_claims'
    | 'unknown' {
    if (!(err instanceof Error)) return 'unknown';

    switch (err.name) {
      case 'TokenExpiredError':
        return 'expired';
      case 'NotBeforeError':
        return 'not_active_yet';
      case 'JsonWebTokenError': {
        const m = (err.message ?? '').toLowerCase();

        if (m.includes('signature')) return 'invalid_signature';
        if (m.includes('malformed')) return 'malformed';

        if (
          m.includes('audience') ||
          m.includes('issuer') ||
          m.includes('subject') ||
          m.includes('claim') ||
          m.includes('invalid')
        ) {
          return 'invalid_claims';
        }

        return 'unknown';
      }
      default:
        return 'unknown';
    }
  }

  async verifyRefreshToken(token: string): Promise<JwtPayload> {
    try {
      return await this.jwt.verifyAsync<JwtPayload>(token, {
        secret: this.getRequired('JWT_REFRESH_SECRET'),
        issuer: this.issuer(),
        audience: this.audience(),
        algorithms: ['HS256'],
      });
    } catch (err: unknown) {
      const reason = this.mapRefreshVerifyErrorToReason(err);

      const appEnv = (
        this.config.get<string>('APP_ENV') ?? 'development'
      ).toLowerCase();

      const meta: Record<string, unknown> = {
        event: 'token.refresh.verify_failed',
        reason,
      };

      if (appEnv !== 'production') {
        meta.errorName = err instanceof Error ? err.name : 'UnknownError';
      }

      this.logger.warn(
        'Refresh token verification failed',
        JwtTokenService.name,
        meta,
      );

      throw new UnauthorizedException('Недійсний refresh токен');
    }
  }
}
