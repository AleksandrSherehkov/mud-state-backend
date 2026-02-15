import { Injectable, UnauthorizedException } from '@nestjs/common';

import { SessionLifecycleService } from 'src/sessions/session-lifecycle.service';
import { AppLogger } from 'src/logger/logger.service';
import { normalizeIp } from 'src/common/net/ip-normalize';
import { hashId, maskIp } from 'src/common/logging/log-sanitize';

import type { JwtPayload } from '../../types/jwt.types';

@Injectable()
export class RefreshIncidentResponseService {
  constructor(
    private readonly lifecycle: SessionLifecycleService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(RefreshIncidentResponseService.name);
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

    this.logger.warn(
      'Refresh reuse detected or token already revoked',
      RefreshIncidentResponseService.name,
      {
        event: 'auth.refresh.reuse_detected',
        userId: params.userId,
        jti: params.payload.jti,
        sid: params.sid,
        ipMasked: nip ? maskIp(nip) : undefined,
        uaHash: ua ? hashId(ua) : undefined,
      },
    );

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
}
