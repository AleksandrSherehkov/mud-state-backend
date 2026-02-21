import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { SessionsService } from 'src/sessions/sessions.service';
import { SessionLifecycleService } from 'src/sessions/session-lifecycle.service';
import { AppLogger } from 'src/logger/logger.service';
import { normalizeIp } from 'src/common/net/ip-normalize';
import { hashId, maskIp } from 'src/common/logging/log-sanitize';

import type { JwtPayload } from '../../types/jwt.types';

type RefreshIncidentStrategy = 'scoped' | 'user_wide';

@Injectable()
export class RefreshIncidentResponseService {
  constructor(
    private readonly sessions: SessionsService,
    private readonly lifecycle: SessionLifecycleService,
    private readonly config: ConfigService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(RefreshIncidentResponseService.name);
  }

  private strategy(): RefreshIncidentStrategy {
    const raw = String(
      this.config.get<string>('REFRESH_INCIDENT_STRATEGY') ?? '',
    )
      .trim()
      .toLowerCase();

    if (raw === 'scoped' || raw === 'user_wide') return raw;

    return 'scoped';
  }

  async handleReuseDetected(params: {
    payload: JwtPayload;
    userId: string;
    sid: string;
    ip?: string;
    userAgent?: string;
  }): Promise<never> {
    const nip = params.ip ? normalizeIp(params.ip) : null;
    const ua = params.userAgent?.trim() || null;

    const binding = await this.sessions.getActiveSessionBinding({
      sid: params.sid,
      userId: params.userId,
    });

    if (
      binding?.refreshTokenJti &&
      binding.refreshTokenJti !== params.payload.jti
    ) {
      this.logger.warn(
        'Refresh claim conflict: likely concurrent rotation (outdated refresh token)',
        RefreshIncidentResponseService.name,
        {
          event: 'auth.refresh.claim_conflict',
          reason: 'rotation_race',
          userId: params.userId,
          sid: params.sid,
          presentedJti: params.payload.jti,
          boundJti: binding.refreshTokenJti,
          ipMasked: nip ? maskIp(nip) : undefined,
          uaHash: ua ? hashId(ua) : undefined,
        },
      );

      throw new ConflictException('Refresh token outdated, retry');
    }

    this.logger.warn(
      'Refresh reuse detected or token already revoked',
      RefreshIncidentResponseService.name,
      {
        event: 'auth.refresh.reuse_detected',
        reason: 'reuse_or_revoked',
        userId: params.userId,
        jti: params.payload.jti,
        sid: params.sid,
        ipMasked: nip ? maskIp(nip) : undefined,
        uaHash: ua ? hashId(ua) : undefined,
      },
    );

    const strategy = this.strategy();

    if (strategy === 'user_wide') {
      const { revokedTokens, terminatedSessions } =
        await this.lifecycle.revokeAllAndTerminateAll({
          userId: params.userId,
          reason: 'refresh_reuse_detected',
        });

      this.logger.warn(
        'Refresh reuse response applied (user-wide revoke all tokens + terminate all sessions)',
        RefreshIncidentResponseService.name,
        {
          event: 'auth.refresh.reuse_response_applied_user_wide',
          userId: params.userId,
          reuseJti: params.payload.jti,
          reuseSid: params.sid,
          revokedTokens,
          terminatedSessions,
        },
      );

      throw new UnauthorizedException('Токен відкликано або недійсний');
    }

    const { revokedTokens, terminatedSessions } =
      await this.lifecycle.revokeJtiAndTerminateSession({
        userId: params.userId,
        jti: params.payload.jti,
        sid: params.sid,
        reason: 'refresh_reuse_detected',
      });

    this.logger.warn(
      'Refresh reuse response applied (scoped revoke jti + terminate sid)',
      RefreshIncidentResponseService.name,
      {
        event: 'auth.refresh.reuse_response_applied_scoped',
        userId: params.userId,
        reuseJti: params.payload.jti,
        reuseSid: params.sid,
        revokedTokens,
        terminatedSessions,
      },
    );

    throw new UnauthorizedException('Токен відкликано або недійсний');
  }
}
