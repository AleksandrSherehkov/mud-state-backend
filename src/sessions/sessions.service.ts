import { Injectable, UnauthorizedException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { normalizeIp } from 'src/common/net/ip-normalize';
import { PrismaService } from 'src/prisma/prisma.service';
import { AppLogger } from 'src/logger/logger.service';
import { maskIp, hashId } from 'src/common/logging/log-sanitize';
import { RefreshTokenService } from './refresh-token.service';
import { RiskEngineService } from 'src/common/security/risk-engine/risk-engine.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class SessionsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly logger: AppLogger,
    private readonly refreshTokenService: RefreshTokenService,
    private readonly risk: RiskEngineService,
    private readonly config: ConfigService,
  ) {
    this.logger.setContext(SessionsService.name);
  }

  async create(
    sessionId: string,
    userId: string,
    refreshTokenJti: string,
    ip?: string,
    userAgent?: string,
    geo?: { country?: string; asn?: number; asOrgHash?: string },
    tx?: Prisma.TransactionClient,
  ) {
    const nip = ip ? normalizeIp(ip) : null;
    const ua = userAgent?.trim() || null;

    const db = tx ?? this.prisma;

    const session = await db.session.create({
      data: {
        id: sessionId,
        userId,
        refreshTokenJti,
        ip: nip,
        userAgent: ua,
        geoCountry: geo?.country ?? null,
        asn: geo?.asn ?? null,
        asOrgHash: geo?.asOrgHash ?? null,
      },
    });

    this.logger.log('Session created', SessionsService.name, {
      event: 'session.created',
      userId,
      sid: sessionId,
      jti: refreshTokenJti,
      ipMasked: nip ? maskIp(nip) : undefined,
      uaHash: ua ? hashId(ua) : undefined,
    });

    return session;
  }

  async getUserSessions(userId: string) {
    return this.prisma.session.findMany({ where: { userId } });
  }

  async getActiveUserSessions(userId: string, take = 50) {
    const sessions = await this.prisma.session.findMany({
      where: { userId, isActive: true },
      orderBy: { startedAt: 'desc' },
      take,
    });

    this.logger.debug('Active sessions fetched', SessionsService.name, {
      event: 'session.list.active',
      userId,
      take,
      returned: sessions.length,
    });

    return sessions;
  }

  async getAllUserSessions(userId: string) {
    const sessions = await this.prisma.session.findMany({
      where: { userId },
      orderBy: { startedAt: 'desc' },
    });

    this.logger.debug('All sessions fetched', SessionsService.name, {
      event: 'session.list.all',
      userId,
      returned: sessions.length,
    });

    return sessions;
  }

  async enforceMaxActiveSessions(params: {
    userId: string;
    maxActive: number;
    meta?: Record<string, unknown>;
    tx: Prisma.TransactionClient;
  }): Promise<{ terminated: number }> {
    const { userId, maxActive, meta, tx } = params;

    const max = Number.isFinite(maxActive) ? Math.floor(maxActive) : 0;
    if (max <= 0) return { terminated: 0 };

    const keep = Math.max(0, max - 1);

    const active = await tx.session.findMany({
      where: { userId, isActive: true, endedAt: null },
      orderBy: { startedAt: 'desc' },
      select: { id: true },
    });

    if (active.length <= keep) {
      this.logger.debug('Session cap ok (no eviction)', SessionsService.name, {
        event: 'session.cap.noop',
        userId,
        maxActive: max,
        keepBeforeCreate: keep,
        active: active.length,
        ...(meta ?? undefined),
      });
      return { terminated: 0 };
    }

    const toTerminateIds = active.slice(keep).map((s) => s.id);

    const terminated = await this.terminateSessions(
      { userId, id: { in: toTerminateIds } },
      {
        userId,
        reason: 'cap_evict_oldest',
        maxActive: max,
        keepBeforeCreate: keep,
        active: active.length,
        evicted: toTerminateIds.length,
        ...(meta ?? undefined),
      },
      tx,
    );

    return { terminated: terminated.count };
  }

  private async terminateSessions(
    where: Prisma.SessionWhereInput,
    meta: Record<string, unknown>,
    tx: Prisma.TransactionClient,
  ): Promise<Prisma.BatchPayload> {
    const sessions = await tx.session.findMany({
      where: { ...where, isActive: true, endedAt: null },
      select: { id: true, refreshTokenJti: true },
    });

    if (sessions.length === 0) {
      this.logger.debug(
        'Terminate sessions: nothing to terminate',
        SessionsService.name,
        {
          event: 'session.terminate.noop',
          ...meta,
        },
      );
      return { count: 0 };
    }

    const now = new Date();
    const sessionIds = sessions.map((s) => s.id);

    const jtis = [
      ...new Set(
        sessions
          .map((s) => s.refreshTokenJti)
          .filter((x): x is string => !!x)
          .map((x) => x.trim())
          .filter(Boolean),
      ),
    ];

    const revoked = jtis.length
      ? await this.refreshTokenService.revokeManyByJtis(jtis, meta, tx)
      : ({ count: 0 } as Prisma.BatchPayload);

    const terminated = await tx.session.updateMany({
      where: { id: { in: sessionIds }, isActive: true, endedAt: null },
      data: { isActive: false, endedAt: now },
    });

    this.logger.log('Sessions terminated', SessionsService.name, {
      event: 'session.terminated',
      count: terminated.count,
      revokedRefreshCount: revoked.count,
      sessionsMatched: sessions.length,
      jtisMatched: jtis.length,
      ...meta,
    });

    return terminated;
  }

  async terminateOtherSessions(userId: string, excludeSessionId: string) {
    return this.prisma.$transaction((tx) =>
      this.terminateSessions(
        { userId, NOT: { id: excludeSessionId } },
        { userId, excludeSid: excludeSessionId, reason: 'others' },
        tx,
      ),
    );
  }

  async terminateAll(userId: string) {
    return this.prisma.$transaction((tx) =>
      this.terminateSessions({ userId }, { userId, reason: 'all' }, tx),
    );
  }

  async terminateByRefreshToken(jti: string) {
    return this.prisma.$transaction((tx) =>
      this.terminateSessions(
        { refreshTokenJti: jti },
        { jti, reason: 'by_refresh_token' },
        tx,
      ),
    );
  }

  async countActive(userId: string): Promise<number> {
    return this.prisma.session.count({ where: { userId, isActive: true } });
  }

  async isSessionActive(sessionId: string, userId: string): Promise<boolean> {
    const session = await this.prisma.session.findFirst({
      where: { id: sessionId, userId, isActive: true, endedAt: null },
      select: { id: true },
    });
    return !!session;
  }
  async getActiveSessionBinding(params: {
    sid: string;
    userId: string;
  }): Promise<{ refreshTokenJti: string | null } | null> {
    const session = await this.prisma.session.findFirst({
      where: {
        id: params.sid,
        userId: params.userId,
        isActive: true,
        endedAt: null,
      },
      select: { refreshTokenJti: true },
    });

    return session
      ? { refreshTokenJti: session.refreshTokenJti ?? null }
      : null;
  }

  async getActiveSessionContext(params: {
    sid: string;
    userId: string;
  }): Promise<{
    refreshTokenJti: string | null;
    geoCountry: string | null;
    asn: number | null;
    asOrgHash: string | null;
  } | null> {
    const session = await this.prisma.session.findFirst({
      where: {
        id: params.sid,
        userId: params.userId,
        isActive: true,
        endedAt: null,
      },
      select: {
        refreshTokenJti: true,
        geoCountry: true,
        asn: true,
        asOrgHash: true,
      },
    });

    return session
      ? {
          refreshTokenJti: session.refreshTokenJti ?? null,
          geoCountry: session.geoCountry ?? null,
          asn: session.asn ?? null,
          asOrgHash: session.asOrgHash ?? null,
        }
      : null;
  }
  async isSessionActiveById(sessionId: string): Promise<boolean> {
    const session = await this.prisma.session.findFirst({
      where: { id: sessionId, isActive: true, endedAt: null },
      select: { id: true },
    });
    return !!session;
  }
  async updateRefreshBinding(params: {
    sid: string;
    userId: string;
    newJti: string;
    ip?: string | null;
    userAgent?: string | null;
    tx?: Prisma.TransactionClient;
  }): Promise<number> {
    const db = params.tx ?? this.prisma;

    const nip = params.ip ? normalizeIp(params.ip) : null;
    const ua = (params.userAgent ?? '').trim() || null;

    const updated = await db.session.updateMany({
      where: {
        id: params.sid,
        userId: params.userId,
        isActive: true,
        endedAt: null,
      },
      data: {
        refreshTokenJti: params.newJti,

        ip: nip,
        userAgent: ua,
      },
    });

    if (updated.count === 0) {
      this.logger.warn(
        'Session refresh binding update failed (session inactive or missing)',
        SessionsService.name,
        {
          event: 'session.refresh_binding.update_failed',
          userId: params.userId,
          sid: params.sid,
          newJti: params.newJti,
          ipMasked: nip ? maskIp(nip) : undefined,
          uaHash: ua ? hashId(ua) : undefined,
        },
      );
    } else {
      this.logger.debug(
        'Session refresh binding updated',
        SessionsService.name,
        {
          event: 'session.refresh_binding.updated',
          userId: params.userId,
          sid: params.sid,
          newJti: params.newJti,
        },
      );
    }
    return updated.count;
  }

  async terminateById(params: {
    sid: string;
    userId: string;
    reason?: string;
  }): Promise<Prisma.BatchPayload> {
    return this.prisma.$transaction((tx) =>
      this.terminateSessions(
        { id: params.sid, userId: params.userId },
        {
          userId: params.userId,
          sid: params.sid,
          reason: params.reason ?? 'by_sid',
        },
        tx,
      ),
    );
  }
  private baseAccessAction(
    key: 'ACCESS_FINGERPRINT_MISMATCH_ACTION' | 'ACCESS_GEO_ASN_ANOMALY_ACTION',
  ): 'terminate' | 'deny' | 'log' {
    const raw = String(this.config.get<string>(key) ?? '')
      .toLowerCase()
      .trim();
    if (raw === 'terminate' || raw === 'deny' || raw === 'log') return raw;

    const env = String(this.config.get<string>('APP_ENV') ?? '').toLowerCase();
    return env === 'production' ? 'terminate' : 'log';
  }

  private accessBindingEnabled(): { bindUa: boolean; bindIp: boolean } {
    return {
      bindUa: Boolean(this.config.get<boolean>('ACCESS_BIND_UA')),
      bindIp: Boolean(this.config.get<boolean>('ACCESS_BIND_IP')),
    };
  }

  private accessAdaptiveEnabled(): boolean {
    return Boolean(this.config.get<boolean>('ACCESS_ANOMALY_ADAPTIVE_ENABLED'));
  }

  private shouldSkipAccessContextCheck(params: {
    bindUa: boolean;
    bindIp: boolean;
    anomalyLogEnabled: boolean;
    baseGeoAction: 'terminate' | 'deny' | 'log';
    adaptiveEnabled: boolean;
  }): boolean {
    return (
      !params.bindUa &&
      !params.bindIp &&
      !params.anomalyLogEnabled &&
      params.baseGeoAction === 'log' &&
      !params.adaptiveEnabled
    );
  }

  private async loadActiveSessionForAccess(params: {
    sid: string;
    userId: string;
  }) {
    return this.prisma.session.findFirst({
      where: {
        id: params.sid,
        userId: params.userId,
        isActive: true,
        endedAt: null,
      },
      select: {
        ip: true,
        userAgent: true,
        geoCountry: true,
        asn: true,
        asOrgHash: true,
      },
    });
  }

  private logAccessContextAnomaly(params: {
    anomalyLogEnabled: boolean;
    userId: string;
    sid: string;
    sessIp: string | null;
    reqIp: string | null;
    sessUa: string | null;
    reqUa: string | null;
    reqIpMasked?: string;
    reqUaHash?: string;
  }) {
    if (!params.anomalyLogEnabled) return;

    const ipChanged =
      !!params.sessIp && !!params.reqIp && params.sessIp !== params.reqIp;
    const uaChanged =
      !!params.sessUa && !!params.reqUa && params.sessUa !== params.reqUa;

    if (!ipChanged && !uaChanged) return;

    this.logger.warn('Access context anomaly', SessionsService.name, {
      event: 'auth.access.anomaly',
      userId: params.userId,
      sid: params.sid,
      ipChanged,
      uaChanged,
      ipMasked: params.reqIpMasked,
      uaHash: params.reqUaHash,
    });
  }

  private normalizeGeo(v?: string | null): string | null {
    return (v ?? '').trim().toUpperCase() || null;
  }

  private async handleGeoAsnAnomaly(params: {
    userId: string;
    sid: string;
    session: {
      geoCountry: string | null;
      asn: number | null;
      asOrgHash: string | null;
    };
    reqGeo: { country?: string; asn?: number; asOrgHash?: string } | undefined;
    baseGeoAction: 'terminate' | 'deny' | 'log';
  }): Promise<void> {
    const sessCountry = this.normalizeGeo(params.session.geoCountry);
    const reqCountry = this.normalizeGeo(params.reqGeo?.country);

    const sessAsn = params.session.asn ?? null;
    const reqAsn =
      typeof params.reqGeo?.asn === 'number' ? params.reqGeo.asn : null;

    const sessOrgHash = params.session.asOrgHash ?? null;
    const reqOrgHash = params.reqGeo?.asOrgHash ?? null;

    const countryMismatch =
      !!sessCountry && !!reqCountry && sessCountry !== reqCountry;
    const asnMismatch =
      sessAsn !== null && reqAsn !== null && sessAsn !== reqAsn;
    const orgMismatch =
      sessOrgHash !== null && reqOrgHash !== null && sessOrgHash !== reqOrgHash;

    if (!countryMismatch && !asnMismatch && !orgMismatch) return;

    const geoAction = await this.risk.decideAccessAnomalyAction({
      kind: 'geo_asn',
      userId: params.userId,
      base: params.baseGeoAction,
      geoMismatchStrong: countryMismatch || asnMismatch,
    });

    this.logger.warn('Access geo/ASN anomaly', SessionsService.name, {
      event: 'auth.access.geo_asn_anomaly',
      userId: params.userId,
      sid: params.sid,
      countryMismatch,
      asnMismatch,
      orgMismatch,
      sessionCountry: sessCountry ?? undefined,
      reqCountry: reqCountry ?? undefined,
      sessionAsn: sessAsn ?? undefined,
      reqAsn: reqAsn ?? undefined,
      geoAction,
    });

    // deny/terminate only on strong mismatch (country/asn)
    if (geoAction === 'log') return;
    if (!countryMismatch && !asnMismatch) return;

    if (geoAction === 'terminate') {
      await this.terminateById({
        sid: params.sid,
        userId: params.userId,
        reason: 'access_geo_asn_anomaly',
      });
    }

    throw new UnauthorizedException('Токен відкликано або недійсний');
  }

  private async handleFingerprintMismatch(params: {
    userId: string;
    sid: string;
    bindUa: boolean;
    bindIp: boolean;
    sessUa: string | null;
    reqUa: string | null;
    sessIp: string | null;
    reqIp: string | null;
    baseAction: 'terminate' | 'deny' | 'log';
    reqIpMasked?: string;
    reqUaHash?: string;
  }): Promise<void> {
    const uaMismatch =
      params.bindUa &&
      !!params.sessUa &&
      (!params.reqUa || params.sessUa !== params.reqUa);
    const ipMismatch =
      params.bindIp &&
      !!params.sessIp &&
      (!params.reqIp || params.sessIp !== params.reqIp);

    if (!uaMismatch && !ipMismatch) return;

    const action = await this.risk.decideAccessAnomalyAction({
      kind: 'fingerprint',
      userId: params.userId,
      base: params.baseAction,
    });

    this.logger.warn('Access fingerprint mismatch', SessionsService.name, {
      event: 'auth.access.fingerprint_mismatch',
      userId: params.userId,
      sid: params.sid,
      bindUa: params.bindUa,
      bindIp: params.bindIp,
      uaMismatch,
      ipMismatch,
      action,
      ipMasked: params.reqIpMasked,
      uaHash: params.reqUaHash,
    });

    if (action === 'log') return;

    if (action === 'terminate') {
      await this.terminateById({
        sid: params.sid,
        userId: params.userId,
        reason: 'access_fingerprint_mismatch',
      });
    }

    throw new UnauthorizedException('Токен відкликано або недійсний');
  }

  async assertAccessContext(params: {
    sid: string;
    userId: string;
    ip?: string | null;
    userAgent?: string | null;
    geo?: { country?: string; asn?: number; asOrgHash?: string };
  }): Promise<void> {
    const { bindUa, bindIp } = this.accessBindingEnabled();
    const anomalyLogEnabled = Boolean(
      this.config.get<boolean>('ACCESS_ANOMALY_LOG'),
    );

    const baseAction = this.baseAccessAction(
      'ACCESS_FINGERPRINT_MISMATCH_ACTION',
    );
    const baseGeoAction = this.baseAccessAction(
      'ACCESS_GEO_ASN_ANOMALY_ACTION',
    );

    const adaptiveEnabled = this.accessAdaptiveEnabled();

    if (
      this.shouldSkipAccessContextCheck({
        bindUa,
        bindIp,
        anomalyLogEnabled,
        baseGeoAction,
        adaptiveEnabled,
      })
    ) {
      return;
    }

    const session = await this.loadActiveSessionForAccess({
      sid: params.sid,
      userId: params.userId,
    });

    if (!session) {
      throw new UnauthorizedException('Токен відкликано або недійсний');
    }

    const reqIp = params.ip ? normalizeIp(params.ip) : null;
    const reqUa = (params.userAgent ?? '').trim() || null;

    const sessIp = session.ip ?? null;
    const sessUa = (session.userAgent ?? '').trim() || null;

    this.logAccessContextAnomaly({
      anomalyLogEnabled,
      userId: params.userId,
      sid: params.sid,
      sessIp,
      reqIp,
      sessUa,
      reqUa,
      reqIpMasked: reqIp ? maskIp(reqIp) : undefined,
      reqUaHash: reqUa ? hashId(reqUa) : undefined,
    });

    await this.handleGeoAsnAnomaly({
      userId: params.userId,
      sid: params.sid,
      session,
      reqGeo: params.geo,
      baseGeoAction,
    });

    await this.handleFingerprintMismatch({
      userId: params.userId,
      sid: params.sid,
      bindUa,
      bindIp,
      sessUa,
      reqUa,
      sessIp,
      reqIp,
      baseAction,
      reqIpMasked: reqIp ? maskIp(reqIp) : undefined,
      reqUaHash: reqUa ? hashId(reqUa) : undefined,
    });
  }
}
