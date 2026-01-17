import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from './types/jwt.types';
import type { StringValue } from 'ms';
import { AppLogger } from 'src/logger/logger.service';

@Injectable()
export class TokenService {
  constructor(
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(TokenService.name);
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
    // Не логируем — слишком шумно и потенциально рискованно.
    return this.jwt.signAsync(payload, { secret, expiresIn });
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
      });
    } catch (err: unknown) {
      // Никаких токенов в логах. Только причина.
      const name = err instanceof Error ? err.name : 'UnknownError';
      const msg = err instanceof Error ? err.message : String(err);

      this.logger.warn('Refresh token verification failed', TokenService.name, {
        event: 'token.refresh.verify_failed',
        errorName: name,
        // message может содержать "jwt expired" и т.п. — ок. токена там не будет.
        errorMessage: msg,
      });

      throw new UnauthorizedException('Недійсний refresh токен');
    }
  }
}
