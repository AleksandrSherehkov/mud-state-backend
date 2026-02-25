import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { PrismaService } from 'src/prisma/prisma.service';
import { AppLogger } from 'src/logger/logger.service';
import { normalizeIp } from 'src/common/net/ip-normalize';
import { maskIp, hashId } from 'src/common/logging/log-sanitize';

import { RiskEngineService } from 'src/common/security/risk-engine/risk-engine.service';
import { SessionTerminationService } from './session-termination.service';
import { AccessAction } from 'src/common/security/types/access-action';

type AccessActionKey =
  | 'ACCESS_FINGERPRINT_MISMATCH_ACTION'
  | 'ACCESS_GEO_ASN_ANOMALY_ACTION';

@Injectable()
export class AccessAnomalyService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly logger: AppLogger,
    private readonly risk: RiskEngineService,
    private readonly config: ConfigService,
    private readonly termination: SessionTerminationService,
  ) {
    this.logger.setContext(AccessAnomalyService.name);
  }

  private baseAccessAction(key: AccessActionKey): AccessAction {
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
    baseGeoAction: AccessAction;
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

    this.logger.warn('Access context anomaly', AccessAnomalyService.name, {
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
    baseGeoAction: AccessAction;
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

    this.logger.warn('Access geo/ASN anomaly', AccessAnomalyService.name, {
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
      await this.termination.terminateById({
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

    this.logger.warn('Access fingerprint mismatch', AccessAnomalyService.name, {
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
      await this.termination.terminateById({
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
