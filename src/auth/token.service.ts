import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from './types/jwt.types';
import type { StringValue } from 'ms';
import { AppLogger } from 'src/logger/logger.service';
import {
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';

const REFRESH_SALT_BYTES = 16;
const SCRYPT_KEYLEN = 32;
const SCRYPT_OPTS = { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };

@Injectable()
export class TokenService {
  constructor(
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(TokenService.name);
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
        TokenService.name,
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
    return randomBytes(REFRESH_SALT_BYTES).toString('hex');
  }
  private hashRefreshTokenLegacy(token: string): string {
    const pepper = this.getRequired('REFRESH_TOKEN_PEPPER');
    return createHmac('sha256', pepper).update(token).digest('hex');
  }
  hashRefreshToken(token: string, salt?: string | null): string {
    if (!salt) return this.hashRefreshTokenLegacy(token);

    const pepper = this.getRequired('REFRESH_TOKEN_PEPPER');
    const s = `${pepper}:${salt}`;

    const dk = scryptSync(token, s, SCRYPT_KEYLEN, SCRYPT_OPTS);
    return dk.toString('hex');
  }
  safeEqualHex(a: string, b: string): boolean {
    const ba = Buffer.from(a, 'hex');
    const bb = Buffer.from(b, 'hex');
    if (ba.length !== bb.length) return false;
    return timingSafeEqual(ba, bb);
  }

  async signAccessToken(payload: JwtPayload): Promise<string> {
    return this.signToken(
      payload,
      this.getRequired('JWT_ACCESS_SECRET'),
      this.config.get<StringValue>(
        'JWT_ACCESS_EXPIRES_IN',
        '15m' as StringValue,
      ),
    );
  }

  async signRefreshToken(payload: JwtPayload): Promise<string> {
    return this.signToken(
      payload,
      this.getRequired('JWT_REFRESH_SECRET'),
      this.config.get<StringValue>(
        'JWT_REFRESH_EXPIRES_IN',
        '7d' as StringValue,
      ),
    );
  }

  async verifyRefreshToken(token: string): Promise<JwtPayload> {
    try {
      return await this.jwt.verifyAsync<JwtPayload>(token, {
        secret: this.getRequired('JWT_REFRESH_SECRET'),
        issuer: this.issuer(),
        audience: this.audience(),
      });
    } catch (err: unknown) {
      const name = err instanceof Error ? err.name : 'UnknownError';
      const msg = err instanceof Error ? err.message : String(err);

      this.logger.warn('Refresh token verification failed', TokenService.name, {
        event: 'token.refresh.verify_failed',
        errorName: name,

        errorMessage: msg,
      });

      throw new UnauthorizedException('Недійсний refresh токен');
    }
  }
}
