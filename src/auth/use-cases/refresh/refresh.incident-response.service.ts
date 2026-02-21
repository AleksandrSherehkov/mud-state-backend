import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { SessionsService } from 'src/sessions/sessions.service';
import { SessionLifecycleService } from 'src/sessions/session-lifecycle.service';
import { AuthSecurityService } from 'src/auth/auth-security.service';

import { AppLogger } from 'src/logger/logger.service';
import { normalizeIp } from 'src/common/net/ip-normalize';
import { hashId, maskIp } from 'src/common/logging/log-sanitize';

import type { JwtPayload } from '../../types/jwt.types';
import { UsersService } from 'src/users/users.service';

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
    private readonly authSecurity: AuthSecurityService,
    private readonly users: UsersService,
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

    const { strategy, escalationReasons } = await this.decideStrategy({
      base: this.baseStrategy(),
      adaptiveEnabled: this.adaptiveEnabled(),
      userId: params.userId,
      sid: params.sid,
      jti: params.payload.jti,
      sessionCtx,
      geo: params.geo ?? null,
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

  private async decideStrategy(params: {
    base: RefreshIncidentStrategy;
    adaptiveEnabled: boolean;
    userId: string;
    sid: string;
    jti: string;
    sessionCtx: SessionCtx | null;
    geo: { country?: string; asn?: number; asOrgHash?: string } | null;
  }): Promise<{
    strategy: RefreshIncidentStrategy;
    escalationReasons: string[];
  }> {
    const escalationReasons: string[] = [];

    if (params.base === 'user_wide' || !params.adaptiveEnabled) {
      return { strategy: params.base, escalationReasons };
    }

    if (await this.shouldEscalateByRole(params.userId)) {
      escalationReasons.push('high_privilege_role');
    }

    if (await this.shouldEscalateByRepeatReuse(params.userId, params.geo)) {
      escalationReasons.push('repeat_reuse');
    }

    if (this.shouldEscalateByGeoAsn(params.sessionCtx, params.geo)) {
      escalationReasons.push('geo_asn_anomaly');
    }

    if (escalationReasons.length === 0) {
      return { strategy: 'scoped', escalationReasons };
    }

    this.logger.warn(
      'Adaptive refresh reuse escalation applied',
      RefreshIncidentResponseService.name,
      {
        event: 'auth.refresh.reuse_escalated',
        userId: params.userId,
        sid: params.sid,
        jti: params.jti,
        reasons: escalationReasons,
      },
    );

    return { strategy: 'user_wide', escalationReasons };
  }

  private async shouldEscalateByRole(userId: string): Promise<boolean> {
    const roles = this.escalateRoles();

    try {
      const role = String(await this.users.getUserRoleById(userId))
        .trim()
        .toUpperCase();

      return Boolean(role && roles.has(role));
    } catch (e) {
      const err = this.safeErr(e);

      this.logger.warn(
        'Role lookup failed during refresh reuse handling',
        RefreshIncidentResponseService.name,
        {
          event: 'auth.refresh.reuse_role_lookup_failed',
          userId,
          errName: err.name,
          errMsg: err.message,
        },
      );

      return false;
    }
  }

  private async shouldEscalateByRepeatReuse(
    userId: string,
    geo: { country?: string; asn?: number; asOrgHash?: string } | null,
  ): Promise<boolean> {
    const reuseRec = await this.authSecurity.recordRefreshReuse({
      userId,
      geo: geo ?? null,
      windowSec: this.repeatWindowSec(),
    });

    return reuseRec.count >= this.repeatThreshold();
  }

  private shouldEscalateByGeoAsn(
    sessionCtx: SessionCtx | null,
    geo: { country?: string; asn?: number; asOrgHash?: string } | null,
  ): boolean {
    if (!this.escalateOnGeoAsn()) return false;
    if (!sessionCtx || !geo) return false;

    const sessCountry =
      (sessionCtx.geoCountry ?? '').trim().toUpperCase() || null;
    const reqCountry = (geo.country ?? '').trim().toUpperCase() || null;

    const sessAsn = sessionCtx.asn ?? null;
    const reqAsn = typeof geo.asn === 'number' ? geo.asn : null;

    const sessOrgHash = sessionCtx.asOrgHash ?? null;
    const reqOrgHash = geo.asOrgHash ?? null;

    const countryMismatch =
      !!sessCountry && !!reqCountry && sessCountry !== reqCountry;

    const asnMismatch =
      sessAsn !== null && reqAsn !== null && sessAsn !== reqAsn;

    const orgMismatch =
      sessOrgHash !== null && reqOrgHash !== null && sessOrgHash !== reqOrgHash;

    return countryMismatch || asnMismatch || orgMismatch;
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

      throw new ConflictException('Refresh token outdated, retry');
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

  private safeErr(e: unknown): { name?: string; message?: string } {
    if (e instanceof Error) return { name: e.name, message: e.message };
    return { name: 'UnknownError', message: String(e) };
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

  private repeatWindowSec(): number {
    const v = Number(this.config.get('REFRESH_REUSE_REPEAT_WINDOW_SEC') ?? 900);
    if (!Number.isFinite(v)) return 900;
    return Math.min(Math.max(Math.floor(v), 60), 86400);
  }

  private repeatThreshold(): number {
    const v = Number(this.config.get('REFRESH_REUSE_REPEAT_THRESHOLD') ?? 2);
    if (!Number.isFinite(v)) return 2;
    return Math.min(Math.max(Math.floor(v), 2), 10);
  }

  private escalateOnGeoAsn(): boolean {
    return Boolean(
      this.config.get<boolean>('REFRESH_REUSE_ESCALATE_ON_GEO_ASN'),
    );
  }

  private escalateRoles(): Set<string> {
    const raw = String(
      this.config.get<string>('REFRESH_REUSE_ESCALATE_ROLES') ??
        'ADMIN,MODERATOR',
    );

    return new Set(
      raw
        .split(',')
        .map((s) => s.trim().toUpperCase())
        .filter((s) => s === 'ADMIN' || s === 'MODERATOR' || s === 'USER'),
    );
  }
}
