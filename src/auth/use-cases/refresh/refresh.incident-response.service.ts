import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { SessionsService } from 'src/sessions/sessions.service';
import { SessionLifecycleService } from 'src/sessions/session-lifecycle.service';

import { AppLogger } from 'src/logger/logger.service';
import { normalizeIp } from 'src/common/net/ip-normalize';
import { hashId, maskIp } from 'src/common/logging/log-sanitize';

import type { JwtPayload } from '../../types/jwt.types';
import { RiskEngineService } from 'src/common/security/risk-engine/risk-engine.service';

type RefreshIncidentStrategy = 'scoped' | 'user_wide';

type SessionCtx = {
  refreshTokenJti: string | null;
  geoCountry: string | null;
  asn: number | null;
  asOrgHash: string | null;
};

type ReqMeta = {
  nip: string | null;
  ua: string | null;
  ipMasked?: string;
  uaHash?: string;
};

@Injectable()
export class RefreshIncidentResponseService {
  constructor(
    private readonly sessions: SessionsService,
    private readonly lifecycle: SessionLifecycleService,
    private readonly risk: RiskEngineService,
    private readonly config: ConfigService,
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
    geo?: { country?: string; asn?: number; asOrgHash?: string };
  }): Promise<never> {
    const meta = this.buildReqMeta(params.ip, params.userAgent);

    const sessionCtx = await this.sessions.getActiveSessionContext({
      sid: params.sid,
      userId: params.userId,
    });

    this.throwIfRotationRace({
      sessionCtx,
      presentedJti: params.payload.jti,
      userId: params.userId,
      sid: params.sid,
      meta,
    });

    this.logReuseDetected({
      userId: params.userId,
      sid: params.sid,
      jti: params.payload.jti,
      meta,
    });

    const { strategy, escalationReasons } =
      await this.risk.decideRefreshReuseStrategy({
        userId: params.userId,
        sid: params.sid,
        jti: params.payload.jti,
        sessionCtx,
        geo: params.geo ?? null,

        base: this.baseStrategy(),
        adaptiveEnabled: this.adaptiveEnabled(),
      });

    await this.applyIncidentResponse({
      strategy,
      userId: params.userId,
      sid: params.sid,
      jti: params.payload.jti,
      escalationReasons,
    });

    throw new UnauthorizedException('Токен відкликано або недійсний');
  }

  private async applyIncidentResponse(params: {
    strategy: RefreshIncidentStrategy;
    userId: string;
    sid: string;
    jti: string;
    escalationReasons: string[];
  }): Promise<never> {
    if (params.strategy === 'user_wide') {
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
          reuseJti: params.jti,
          reuseSid: params.sid,
          revokedTokens,
          terminatedSessions,
          escalationReasons: params.escalationReasons.length
            ? params.escalationReasons
            : undefined,
        },
      );

      throw new UnauthorizedException('Токен відкликано або недійсний');
    }

    const { revokedTokens, terminatedSessions } =
      await this.lifecycle.revokeJtiAndTerminateSession({
        userId: params.userId,
        jti: params.jti,
        sid: params.sid,
        reason: 'refresh_reuse_detected',
      });

    this.logger.warn(
      'Refresh reuse response applied (scoped revoke jti + terminate sid)',
      RefreshIncidentResponseService.name,
      {
        event: 'auth.refresh.reuse_response_applied_scoped',
        userId: params.userId,
        reuseJti: params.jti,
        reuseSid: params.sid,
        revokedTokens,
        terminatedSessions,
      },
    );

    throw new UnauthorizedException('Токен відкликано або недійсний');
  }

  private throwIfRotationRace(params: {
    sessionCtx: SessionCtx | null;
    presentedJti: string;
    userId: string;
    sid: string;
    meta: ReqMeta;
  }): void {
    const bound = params.sessionCtx?.refreshTokenJti;

    if (bound && bound !== params.presentedJti) {
      this.logger.warn(
        'Refresh claim conflict: likely concurrent rotation (outdated refresh token)',
        RefreshIncidentResponseService.name,
        {
          event: 'auth.refresh.claim_conflict',
          reason: 'rotation_race',
          userId: params.userId,
          sid: params.sid,
          presentedJti: params.presentedJti,
          boundJti: bound,
          ipMasked: params.meta.ipMasked,
          uaHash: params.meta.uaHash,
        },
      );

      throw new UnauthorizedException('Токен відкликано або недійсний');
    }
  }

  private logReuseDetected(params: {
    userId: string;
    sid: string;
    jti: string;
    meta: ReqMeta;
  }): void {
    this.logger.warn(
      'Refresh reuse detected or token already revoked',
      RefreshIncidentResponseService.name,
      {
        event: 'auth.refresh.reuse_detected',
        reason: 'reuse_or_revoked',
        userId: params.userId,
        jti: params.jti,
        sid: params.sid,
        ipMasked: params.meta.ipMasked,
        uaHash: params.meta.uaHash,
      },
    );
  }

  private buildReqMeta(ip?: string, userAgent?: string): ReqMeta {
    const nip = ip ? normalizeIp(ip) : null;
    const ua = userAgent?.trim() || null;

    return {
      nip,
      ua,
      ipMasked: nip ? maskIp(nip) : undefined,
      uaHash: ua ? hashId(ua) : undefined,
    };
  }

  private baseStrategy(): RefreshIncidentStrategy {
    const raw = String(
      this.config.get<string>('REFRESH_INCIDENT_STRATEGY') ?? '',
    )
      .trim()
      .toLowerCase();

    if (raw === 'scoped' || raw === 'user_wide') return raw;
    return 'scoped';
  }

  private adaptiveEnabled(): boolean {
    return Boolean(this.config.get<boolean>('REFRESH_REUSE_ADAPTIVE_ENABLED'));
  }
}
