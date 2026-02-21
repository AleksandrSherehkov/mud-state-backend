import { Injectable, UnauthorizedException } from '@nestjs/common';
import { Role } from '@prisma/client';

import { JwtTokenService } from '../../jwtTokenService';
import { UsersService } from 'src/users/users.service';
import { SessionsService } from 'src/sessions/sessions.service';

import { AppLogger } from 'src/logger/logger.service';
import { normalizeIp } from 'src/common/net/ip-normalize';
import { hashId, maskIp } from 'src/common/logging/log-sanitize';

import type { JwtPayload } from '../../types/jwt.types';

function isUuid(v: string): boolean {
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      v,
    )
  ) {
    return false;
  }

  return v.toLowerCase() !== '00000000-0000-0000-0000-000000000000';
}

@Injectable()
export class RefreshVerifier {
  constructor(
    private readonly jwtTokenService: JwtTokenService,
    private readonly usersService: UsersService,
    private readonly sessionsService: SessionsService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(RefreshVerifier.name);
  }

  async verifyRefreshOrThrow(refreshToken: string): Promise<JwtPayload> {
    try {
      return await this.jwtTokenService.verifyRefreshToken(refreshToken);
    } catch {
      this.logger.warn(
        'Refresh failed: invalid token signature',
        RefreshVerifier.name,
        {
          event: 'auth.refresh.fail',
          reason: 'invalid_token',
        },
      );
      throw new UnauthorizedException('Недійсний токен');
    }
  }

  requireJti(payload: JwtPayload): string {
    const raw = (payload.jti ?? '').trim();

    if (!raw) {
      this.logger.warn(
        'Refresh failed: missing jti in token',
        RefreshVerifier.name,
        {
          event: 'auth.refresh.fail',
          reason: 'missing_jti',
          sid: payload.sid,
          sub: payload.sub,
        },
      );
      throw new UnauthorizedException('Недійсний токен');
    }

    if (!isUuid(raw)) {
      this.logger.warn(
        'Refresh failed: invalid jti format',
        RefreshVerifier.name,
        {
          event: 'auth.refresh.fail',
          reason: 'invalid_jti',
          sid: payload.sid,
          sub: payload.sub,
        },
      );
      throw new UnauthorizedException('Недійсний токен');
    }

    return raw;
  }

  requireUserId(payload: JwtPayload): string {
    const userId = payload.sub;
    if (!userId) {
      this.logger.warn(
        'Refresh failed: missing sub in token',
        RefreshVerifier.name,
        {
          event: 'auth.refresh.fail',
          reason: 'missing_sub',
          jti: payload.jti,
          sid: payload.sid,
        },
      );
      throw new UnauthorizedException('Недійсний токен');
    }
    return userId;
  }

  requireSid(payload: JwtPayload, userId: string): string {
    if (!payload.sid) {
      this.logger.warn(
        'Refresh failed: session missing in token',
        RefreshVerifier.name,
        {
          event: 'auth.refresh.fail',
          reason: 'missing_sid',
          userId,
          jti: payload.jti,
        },
      );
      throw new UnauthorizedException('Недійсний токен');
    }
    return payload.sid;
  }

  async assertSessionActiveOrThrow(params: {
    sid: string;
    userId: string;
    payload: JwtPayload;
    ip?: string;
    userAgent?: string;
  }): Promise<void> {
    const active = await this.sessionsService.isSessionActive(
      params.sid,
      params.userId,
    );
    if (active) return;

    const nip = params.ip ? normalizeIp(params.ip) : null;
    const ua = params.userAgent?.trim() || null;

    this.logger.warn(
      'Refresh blocked: session is not active',
      RefreshVerifier.name,
      {
        event: 'auth.refresh.blocked',
        reason: 'session_inactive',
        userId: params.userId,
        jti: params.payload.jti,
        sid: params.sid,
        ipMasked: nip ? maskIp(nip) : undefined,
        uaHash: ua ? hashId(ua) : undefined,
      },
    );

    throw new UnauthorizedException('Сесію завершено або недійсна');
  }

  async getUserOrThrow(
    userId: string,
    payload: JwtPayload,
  ): Promise<{ id: string; email: string; role: Role }> {
    const user = await this.usersService.findById(userId);
    if (user) return user;

    this.logger.warn('Refresh failed: user not found', RefreshVerifier.name, {
      event: 'auth.refresh.fail',
      reason: 'user_not_found',
      userId,
      jti: payload.jti,
      sid: payload.sid,
    });

    throw new UnauthorizedException('Користувача не знайдено');
  }
}
