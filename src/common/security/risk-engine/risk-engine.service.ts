import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { PrismaService } from 'src/prisma/prisma.service';
import { UsersService } from 'src/users/users.service';
import { AppLogger } from 'src/logger/logger.service';

type AccessAction = 'terminate' | 'deny' | 'log';
type RefreshIncidentStrategy = 'scoped' | 'user_wide';

type SessionCtx = {
  refreshTokenJti: string | null;
  geoCountry: string | null;
  asn: number | null;
  asOrgHash: string | null;
};

@Injectable()
export class RiskEngineService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly users: UsersService,
    private readonly config: ConfigService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(RiskEngineService.name);
  }

  // ============================================================
  // ACCESS anomaly
  // ============================================================

  private accessAdaptiveEnabled(): boolean {
    return Boolean(this.config.get<boolean>('ACCESS_ANOMALY_ADAPTIVE_ENABLED'));
  }

  private accessRepeatWindowSec(): number {
    const v = Number(
      this.config.get('ACCESS_ANOMALY_REPEAT_WINDOW_SEC') ?? 900,
    );
    if (!Number.isFinite(v)) return 900;
    return Math.min(Math.max(Math.floor(v), 60), 86400);
  }

  private accessRepeatThreshold(): number {
    const v = Number(this.config.get('ACCESS_ANOMALY_REPEAT_THRESHOLD') ?? 2);
    if (!Number.isFinite(v)) return 2;
    return Math.min(Math.max(Math.floor(v), 2), 10);
  }

  private accessEscalateOnGeoAsn(): boolean {
    return Boolean(
      this.config.get<boolean>('ACCESS_ANOMALY_ESCALATE_ON_GEO_ASN'),
    );
  }

  private accessEscalateRoles(): Set<string> {
    const raw = String(
      this.config.get<string>('ACCESS_ANOMALY_ESCALATE_ROLES') ??
        'ADMIN,MODERATOR',
    );

    return new Set(
      raw
        .split(',')
        .map((s) => s.trim().toUpperCase())
        .filter((s) => s === 'ADMIN' || s === 'MODERATOR' || s === 'USER'),
    );
  }

  private async bumpAccessAnomalyCounter(
    userId: string,
  ): Promise<{ count: number }> {
    const windowSec = this.accessRepeatWindowSec();
    const now = new Date();

    const prev = await this.prisma.userSecurity.findUnique({
      where: { userId },
      select: { accessAnomalyCount: true, lastAccessAnomalyAt: true },
    });

    const windowExpired =
      !prev?.lastAccessAnomalyAt ||
      (now.getTime() - prev.lastAccessAnomalyAt.getTime()) / 1000 > windowSec;

    const nextCount = windowExpired ? 1 : (prev?.accessAnomalyCount ?? 0) + 1;

    const updated = await this.prisma.userSecurity.upsert({
      where: { userId },
      create: {
        userId,
        accessAnomalyCount: nextCount,
        lastAccessAnomalyAt: now,
      },
      update: {
        accessAnomalyCount: nextCount,
        lastAccessAnomalyAt: now,
      },
      select: { accessAnomalyCount: true },
    });

    return { count: updated.accessAnomalyCount };
  }

  private async shouldEscalateAccessByRole(userId: string): Promise<boolean> {
    const roles = this.accessEscalateRoles();

    try {
      const role = String(await this.users.getUserRoleById(userId))
        .trim()
        .toUpperCase();
      return Boolean(role && roles.has(role));
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      this.logger.warn(
        'Access anomaly role lookup failed',
        RiskEngineService.name,
        {
          event: 'risk.access.role_lookup_failed',
          userId,
          errName: err.name,
          errMsg: err.message,
        },
      );
      return false;
    }
  }

  /**
   * Решение: terminate | deny | log
   * - base: текущая политика из env (terminate/deny/log)
   * - kind: fingerprint | geo_asn
   * - geoMismatchStrong: для geo_asn - (countryMismatch || asnMismatch)
   */
  async decideAccessAnomalyAction(params: {
    kind: 'fingerprint' | 'geo_asn';
    userId: string;
    base: AccessAction;
    geoMismatchStrong?: boolean;
  }): Promise<AccessAction> {
    let action: AccessAction = params.base;

    if (!this.accessAdaptiveEnabled()) return action;

    const shouldEscalateByRole = await this.shouldEscalateAccessByRole(
      params.userId,
    );

    const { count } = await this.bumpAccessAnomalyCounter(params.userId);
    const shouldEscalateByRepeat = count >= this.accessRepeatThreshold();

    const shouldEscalateByGeo =
      params.kind === 'geo_asn' &&
      this.accessEscalateOnGeoAsn() &&
      Boolean(params.geoMismatchStrong);

    const escalate =
      shouldEscalateByRole || shouldEscalateByRepeat || shouldEscalateByGeo;
    if (!escalate) return action;

    // escalation ladder
    if (action === 'log') action = 'deny';

    // stronger triggers -> terminate
    if (shouldEscalateByRole || shouldEscalateByRepeat) {
      action = 'terminate';
    }

    this.logger.warn(
      'Access anomaly escalation applied',
      RiskEngineService.name,
      {
        event: 'risk.access.escalated',
        userId: params.userId,
        kind: params.kind,
        base: params.base,
        decided: action,
        reasonRole: shouldEscalateByRole,
        reasonRepeat: shouldEscalateByRepeat,
        reasonGeo: shouldEscalateByGeo,
        repeatCount: count,
      },
    );

    return action;
  }

  // ============================================================
  // REFRESH reuse incident
  // ============================================================

  private refreshAdaptiveEnabled(): boolean {
    return Boolean(this.config.get<boolean>('REFRESH_REUSE_ADAPTIVE_ENABLED'));
  }

  private refreshBaseStrategy(): RefreshIncidentStrategy {
    const raw = String(
      this.config.get<string>('REFRESH_INCIDENT_STRATEGY') ?? '',
    )
      .trim()
      .toLowerCase();

    if (raw === 'scoped' || raw === 'user_wide') return raw;
    return 'scoped';
  }

  private refreshRepeatWindowSec(): number {
    const v = Number(this.config.get('REFRESH_REUSE_REPEAT_WINDOW_SEC') ?? 900);
    if (!Number.isFinite(v)) return 900;
    return Math.min(Math.max(Math.floor(v), 60), 86400);
  }

  private refreshRepeatThreshold(): number {
    const v = Number(this.config.get('REFRESH_REUSE_REPEAT_THRESHOLD') ?? 2);
    if (!Number.isFinite(v)) return 2;
    return Math.min(Math.max(Math.floor(v), 2), 10);
  }

  private refreshEscalateOnGeoAsn(): boolean {
    return Boolean(
      this.config.get<boolean>('REFRESH_REUSE_ESCALATE_ON_GEO_ASN'),
    );
  }

  private refreshEscalateRoles(): Set<string> {
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

  private async shouldEscalateRefreshByRole(userId: string): Promise<boolean> {
    const roles = this.refreshEscalateRoles();

    try {
      const role = String(await this.users.getUserRoleById(userId))
        .trim()
        .toUpperCase();
      return Boolean(role && roles.has(role));
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      this.logger.warn(
        'Refresh reuse role lookup failed',
        RiskEngineService.name,
        {
          event: 'risk.refresh.role_lookup_failed',
          userId,
          errName: err.name,
          errMsg: err.message,
        },
      );
      return false;
    }
  }

  private shouldEscalateRefreshByGeoAsn(
    sessionCtx: SessionCtx | null,
    geo: { country?: string; asn?: number; asOrgHash?: string } | null,
  ): boolean {
    if (!this.refreshEscalateOnGeoAsn()) return false;
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

  private async recordRefreshReuse(params: {
    userId: string;
    geo?: { country?: string; asn?: number; asOrgHash?: string } | null;
    windowSec: number;
  }): Promise<{ count: number; windowExpired: boolean }> {
    const ts = new Date();

    const prev = await this.prisma.userSecurity.findUnique({
      where: { userId: params.userId },
      select: { refreshReuseCount: true, lastRefreshReuseAt: true },
    });

    const windowExpired =
      !prev?.lastRefreshReuseAt ||
      (ts.getTime() - prev.lastRefreshReuseAt.getTime()) / 1000 >
        params.windowSec;

    const nextCount = windowExpired ? 1 : (prev?.refreshReuseCount ?? 0) + 1;
    const country = (params.geo?.country ?? '').trim().toUpperCase() || null;

    await this.prisma.userSecurity.upsert({
      where: { userId: params.userId },
      create: {
        userId: params.userId,
        refreshReuseCount: nextCount,
        lastRefreshReuseAt: ts,
        lastRefreshReuseCountry: country,
        lastRefreshReuseAsn:
          typeof params.geo?.asn === 'number' ? params.geo.asn : null,
        lastRefreshReuseAsOrgHash: params.geo?.asOrgHash ?? null,
      },
      update: {
        refreshReuseCount: nextCount,
        lastRefreshReuseAt: ts,
        lastRefreshReuseCountry: country,
        lastRefreshReuseAsn:
          typeof params.geo?.asn === 'number' ? params.geo.asn : null,
        lastRefreshReuseAsOrgHash: params.geo?.asOrgHash ?? null,
      },
    });

    this.logger.warn('Refresh reuse recorded', RiskEngineService.name, {
      event: 'risk.refresh.reuse.recorded',
      userId: params.userId,
      count: nextCount,
      windowExpired,
      geoCountry: country ?? undefined,
      geoAsn: typeof params.geo?.asn === 'number' ? params.geo.asn : undefined,
      asOrgHash: params.geo?.asOrgHash ?? undefined,
    });

    return { count: nextCount, windowExpired };
  }

  async decideRefreshReuseStrategy(params: {
    userId: string;
    sid: string;
    jti: string;
    sessionCtx: SessionCtx | null;
    geo: { country?: string; asn?: number; asOrgHash?: string } | null;
    // если хочешь override — можно передавать base/adaptive, иначе берём из env
    base?: RefreshIncidentStrategy;
    adaptiveEnabled?: boolean;
  }): Promise<{
    strategy: RefreshIncidentStrategy;
    escalationReasons: string[];
  }> {
    const base = params.base ?? this.refreshBaseStrategy();
    const adaptiveEnabled =
      params.adaptiveEnabled ?? this.refreshAdaptiveEnabled();

    const escalationReasons: string[] = [];

    if (base === 'user_wide' || !adaptiveEnabled) {
      return { strategy: base, escalationReasons };
    }

    const byRole = await this.shouldEscalateRefreshByRole(params.userId);
    if (byRole) escalationReasons.push('high_privilege_role');

    const reuseRec = await this.recordRefreshReuse({
      userId: params.userId,
      geo: params.geo ?? null,
      windowSec: this.refreshRepeatWindowSec(),
    });
    const byRepeat = reuseRec.count >= this.refreshRepeatThreshold();
    if (byRepeat) escalationReasons.push('repeat_reuse');

    const byGeo = this.shouldEscalateRefreshByGeoAsn(
      params.sessionCtx,
      params.geo ?? null,
    );
    if (byGeo) escalationReasons.push('geo_asn_anomaly');

    if (escalationReasons.length === 0) {
      return { strategy: 'scoped', escalationReasons };
    }

    this.logger.warn(
      'Adaptive refresh reuse escalation applied',
      RiskEngineService.name,
      {
        event: 'risk.refresh.reuse_escalated',
        userId: params.userId,
        sid: params.sid,
        jti: params.jti,
        reasons: escalationReasons,
      },
    );

    return { strategy: 'user_wide', escalationReasons };
  }
}
