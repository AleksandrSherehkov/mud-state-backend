import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from './types/jwt.types';
import type { StringValue } from 'ms';

@Injectable()
export class TokenService {
  constructor(
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  private async signToken(
    payload: JwtPayload,
    secret: string,
    expiresIn: StringValue | number,
  ): Promise<string> {
    return this.jwt.signAsync(payload, { secret, expiresIn });
  }

  async signAccessToken(payload: JwtPayload): Promise<string> {
    return this.signToken(
      payload,
      this.config.get<string>('JWT_ACCESS_SECRET')!,
      this.config.get<StringValue>(
        'JWT_ACCESS_EXPIRES_IN',
        '15m' as StringValue,
      ),
    );
  }

  async signRefreshToken(payload: JwtPayload): Promise<string> {
    return this.signToken(
      payload,
      this.config.get<string>('JWT_REFRESH_SECRET')!,
      this.config.get<StringValue>(
        'JWT_REFRESH_EXPIRES_IN',
        '7d' as StringValue,
      ),
    );
  }

  async verifyRefreshToken(token: string): Promise<JwtPayload> {
    try {
      return await this.jwt.verifyAsync(token, {
        secret: this.config.get<string>('JWT_REFRESH_SECRET'),
      });
    } catch {
      throw new UnauthorizedException('Недійсний refresh токен');
    }
  }
}
