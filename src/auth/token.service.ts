import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from './types/jwt.types';

@Injectable()
export class TokenService {
  constructor(
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  private async signToken(
    payload: JwtPayload,
    secret: string,
    expiresIn: string,
  ): Promise<string> {
    return this.jwt.signAsync(payload, { secret, expiresIn });
  }

  async signAccessToken(payload: JwtPayload): Promise<string> {
    return this.signToken(
      payload,
      this.config.get<string>('JWT_ACCESS_SECRET')!,
      this.config.get<string>('JWT_ACCESS_EXPIRES_IN', '15m'),
    );
  }

  async signRefreshToken(payload: JwtPayload): Promise<string> {
    return this.signToken(
      payload,
      this.config.get<string>('JWT_REFRESH_SECRET')!,
      this.config.get<string>('JWT_REFRESH_EXPIRES_IN', '7d'),
    );
  }

  async verifyRefreshToken(token: string): Promise<JwtPayload> {
    try {
      return await this.jwt.verifyAsync(token, {
        secret: this.config.get<string>('JWT_REFRESH_SECRET'),
      });
    } catch (err) {
      throw new UnauthorizedException('Недійсний refresh токен');
    }
  }
}
