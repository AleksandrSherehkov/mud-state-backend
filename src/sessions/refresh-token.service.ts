import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AppLogger } from 'src/logger/logger.service';
import { maskIp, hashId } from 'src/common/helpers/log-sanitize';
import { Prisma } from '@prisma/client';
import { normalizeIp } from 'src/common/helpers/ip-normalize';
import { ConfigService } from '@nestjs/config';

import * as ms from 'ms';

@Injectable()
export class RefreshTokenService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly logger: AppLogger,
    private readonly config: ConfigService,
  ) {
    this.logger.setContext(RefreshTokenService.name);
  }
  private tryParseMs(raw: string): number | undefined {
    const v = ms(raw as ms.StringValue);
    return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
  }

  private calcExpiresAt(): Date {
    const raw = this.config.get<string>('JWT_REFRESH_EXPIRES_IN') ?? '7d';
    const ttl = this.tryParseMs(raw) ?? 7 * 24 * 60 * 60 * 1000;
    return new Date(Date.now() + ttl);
  }

  async create(
    userId: string,
    jti: string,
    tokenHash: string,
    tokenSalt: string,
    ip?: string,
    userAgent?: string,
    tx?: Prisma.TransactionClient,
  ) {
    const db = tx ?? this.prisma;

    const nip = ip ? normalizeIp(ip) : undefined;
    const ua = userAgent?.trim() || undefined;

    const expiresAt = this.calcExpiresAt();

    const token = await db.refreshToken.create({
      data: {
        userId,
        jti,
        tokenSalt,
        tokenHash,
        ip: nip,
        userAgent: ua,
        expiresAt,
      },
    });

    this.logger.log('Refresh token created', RefreshTokenService.name, {
      event: 'refresh_token.created',
      userId,
      jti,
      hasSalt: Boolean(tokenSalt),
      ipMasked: nip ? maskIp(nip) : undefined,
      uaHash: ua ? hashId(ua) : undefined,
    });

    return token;
  }

  async getActiveTokens(userId: string, take = 50) {
    const tokens = await this.prisma.refreshToken.findMany({
      where: { userId, revoked: false, expiresAt: { gt: new Date() } },
      orderBy: { createdAt: 'desc' },
      take,
    });

    this.logger.debug(
      'Active refresh tokens fetched',
      RefreshTokenService.name,
      {
        event: 'refresh_token.list.active',
        userId,
        take,
        returned: tokens.length,
      },
    );

    return tokens;
  }

  async revokeIfActiveByHash(jti: string, userId: string, tokenHash: string) {
    const result = await this.prisma.refreshToken.updateMany({
      where: { jti, userId, tokenHash, revoked: false },
      data: { revoked: true },
    });

    if (result.count === 1) {
      this.logger.log('Refresh token claimed', RefreshTokenService.name, {
        event: 'refresh_token.claimed',
        userId,
        jti,
      });
    } else {
      this.logger.warn('Refresh token claim failed', RefreshTokenService.name, {
        event: 'refresh_token.claim_failed',
        userId,
        jti,
        count: result.count,
      });
    }

    return result;
  }

  async revokeAll(userId: string) {
    const result = await this.prisma.refreshToken.updateMany({
      where: { userId, revoked: false },
      data: { revoked: true },
    });

    if (result.count > 0) {
      this.logger.log(
        'Refresh tokens revoked (all)',
        RefreshTokenService.name,
        {
          event: 'refresh_token.revoked_all',
          userId,
          count: result.count,
        },
      );
    } else {
      this.logger.debug(
        'Revoke all refresh tokens: nothing to revoke',
        RefreshTokenService.name,
        { event: 'refresh_token.revoke_all.noop', userId },
      );
    }

    return result;
  }

  async revokeByJti(jti: string) {
    const token = await this.prisma.refreshToken.update({
      where: { jti },
      data: { revoked: true },
    });

    this.logger.log('Refresh token revoked', RefreshTokenService.name, {
      event: 'refresh_token.revoked',
      jti,
      userId: token.userId,
    });

    return token;
  }

  async validate(jti: string, userId: string) {
    const token = await this.prisma.refreshToken.findUnique({ where: { jti } });

    if (!token) {
      this.logger.warn(
        'Refresh token validation failed: not found',
        RefreshTokenService.name,
        {
          event: 'refresh_token.validate_failed',
          reason: 'not_found',
          userId,
          jti,
        },
      );
      throw new UnauthorizedException('Токен відкликано або недійсний');
    }

    if (token.revoked) {
      this.logger.warn(
        'Refresh token validation failed: revoked',
        RefreshTokenService.name,
        {
          event: 'refresh_token.validate_failed',
          reason: 'revoked',
          userId,
          jti,
        },
      );
      throw new UnauthorizedException('Токен відкликано або недійсний');
    }
    if (token.expiresAt.getTime() <= Date.now()) {
      this.logger.warn(
        'Refresh token validation failed: expired',
        RefreshTokenService.name,
        {
          event: 'refresh_token.validate_failed',
          reason: 'expired',
          userId,
          jti,
          expiresAt: token.expiresAt.toISOString(),
        },
      );
      throw new UnauthorizedException('Токен відкликано або недійсний');
    }

    if (token.userId !== userId) {
      this.logger.warn(
        'Refresh token validation failed: user mismatch',
        RefreshTokenService.name,
        {
          event: 'refresh_token.validate_failed',
          reason: 'user_mismatch',
          userId,
          tokenUserId: token.userId,
          jti,
        },
      );
      throw new UnauthorizedException('Токен відкликано або недійсний');
    }
  }

  async findValid(userId: string, jti: string) {
    return this.prisma.refreshToken.findFirst({
      where: { userId, jti, revoked: false, expiresAt: { gt: new Date() } },
    });
  }

  async countActive(userId: string) {
    return this.prisma.refreshToken.count({
      where: { userId, revoked: false, expiresAt: { gt: new Date() } },
    });
  }

  async revokeManyByJtis(
    jtis: string[],
    meta?: Record<string, unknown>,
    tx?: Prisma.TransactionClient,
  ): Promise<Prisma.BatchPayload> {
    const uniq = [...new Set(jtis.map((x) => x?.trim()).filter(Boolean))];

    if (uniq.length === 0) {
      this.logger.debug(
        'Revoke many refresh tokens: empty list',
        RefreshTokenService.name,
        { event: 'refresh_token.revoke_many.noop', reason: 'empty', ...meta },
      );
      return { count: 0 };
    }

    const db = tx ?? this.prisma;

    const result = await db.refreshToken.updateMany({
      where: { jti: { in: uniq }, revoked: false },
      data: { revoked: true },
    });

    if (result.count > 0) {
      this.logger.log(
        'Refresh tokens revoked (many)',
        RefreshTokenService.name,
        {
          event: 'refresh_token.revoked_many',
          count: result.count,
          jtisCount: uniq.length,
          ...meta,
        },
      );
    } else {
      this.logger.debug(
        'Revoke many refresh tokens: nothing to revoke',
        RefreshTokenService.name,
        {
          event: 'refresh_token.revoked_many.noop',
          jtisCount: uniq.length,
          ...meta,
        },
      );
    }

    return result;
  }

  private isFingerprintBindingEnabled(): { bindUa: boolean; bindIp: boolean } {
    const bindUa = Boolean(this.config.get<boolean>('REFRESH_BIND_UA'));
    const bindIp = Boolean(this.config.get<boolean>('REFRESH_BIND_IP'));
    return { bindUa, bindIp };
  }

  private normalizeFingerprint(params: {
    ip?: string | null;
    userAgent?: string | null;
  }) {
    const reqIp = params.ip ? normalizeIp(params.ip) : null;
    const reqUa = (params.userAgent ?? '').trim() || null;
    return { reqIp, reqUa };
  }

  private normalizeStored(ip?: string | null, ua?: string | null) {
    const nIp = ip ?? null;
    const nUa = (ua ?? '').trim() || null;
    return { ip: nIp, ua: nUa };
  }

  private computeMismatch(opts: {
    bindUa: boolean;
    bindIp: boolean;
    reqIp: string | null;
    reqUa: string | null;
    tokenIp: string | null;
    tokenUa: string | null;
    sessIp: string | null;
    sessUa: string | null;
  }) {
    const uaMismatch =
      opts.bindUa &&
      ((!!opts.tokenUa && (!opts.reqUa || opts.tokenUa !== opts.reqUa)) ||
        (!!opts.sessUa && (!opts.reqUa || opts.sessUa !== opts.reqUa)));

    const ipMismatch =
      opts.bindIp &&
      ((!!opts.tokenIp && (!opts.reqIp || opts.tokenIp !== opts.reqIp)) ||
        (!!opts.sessIp && (!opts.reqIp || opts.sessIp !== opts.reqIp)));

    return { uaMismatch, ipMismatch };
  }

  private async applyFingerprintMismatchResponse(params: {
    userId: string;
    jti: string;
    sid: string;
  }) {
    const now = new Date();

    await this.prisma.$transaction([
      this.prisma.refreshToken.updateMany({
        where: { userId: params.userId, jti: params.jti, revoked: false },
        data: { revoked: true },
      }),
      this.prisma.session.updateMany({
        where: {
          id: params.sid,
          userId: params.userId,
          isActive: true,
          endedAt: null,
        },
        data: { isActive: false, endedAt: now },
      }),
    ]);
  }

  private logFingerprintMismatch(params: {
    userId: string;
    jti: string;
    sid: string;
    bindUa: boolean;
    bindIp: boolean;
    ipMismatch: boolean;
    uaMismatch: boolean;
    tokenIp: string | null;
    sessIp: string | null;
    reqIp: string | null;
    tokenUa: string | null;
    sessUa: string | null;
    reqUa: string | null;
  }) {
    this.logger.warn('Refresh fingerprint mismatch', RefreshTokenService.name, {
      event: 'auth.refresh.fingerprint_mismatch',
      userId: params.userId,
      jti: params.jti,
      sid: params.sid,
      bindUa: params.bindUa,
      bindIp: params.bindIp,
      ipMismatch: params.ipMismatch,
      uaMismatch: params.uaMismatch,
      tokenIpMasked: params.tokenIp ? maskIp(params.tokenIp) : undefined,
      sessionIpMasked: params.sessIp ? maskIp(params.sessIp) : undefined,
      reqIpMasked: params.reqIp ? maskIp(params.reqIp) : undefined,
      tokenUaHash: params.tokenUa ? hashId(params.tokenUa) : undefined,
      sessionUaHash: params.sessUa ? hashId(params.sessUa) : undefined,
      reqUaHash: params.reqUa ? hashId(params.reqUa) : undefined,
    });
  }

  private logFingerprintMismatchApplied(params: {
    userId: string;
    jti: string;
    sid: string;
  }) {
    this.logger.warn(
      'Refresh fingerprint mismatch response applied (scoped revoke + terminate)',
      RefreshTokenService.name,
      {
        event: 'auth.refresh.fingerprint_mismatch_response_applied',
        userId: params.userId,
        jti: params.jti,
        sid: params.sid,
      },
    );
  }

  async assertFingerprint(params: {
    userId: string;
    jti: string;
    sid: string;
    ip?: string | null;
    userAgent?: string | null;
  }) {
    const { bindUa, bindIp } = this.isFingerprintBindingEnabled();
    if (!bindUa && !bindIp) return;

    const [token, session] = await Promise.all([
      this.prisma.refreshToken.findFirst({
        where: { userId: params.userId, jti: params.jti, revoked: false },
        select: { ip: true, userAgent: true },
      }),
      this.prisma.session.findFirst({
        where: {
          id: params.sid,
          userId: params.userId,
          refreshTokenJti: params.jti,
          isActive: true,
          endedAt: null,
        },
        select: { ip: true, userAgent: true },
      }),
    ]);

    if (!token || !session) {
      throw new UnauthorizedException('Токен відкликано або недійсний');
    }

    const { reqIp, reqUa } = this.normalizeFingerprint(params);

    const { ip: tokenIp, ua: tokenUa } = this.normalizeStored(
      token.ip,
      token.userAgent,
    );
    const { ip: sessIp, ua: sessUa } = this.normalizeStored(
      session.ip,
      session.userAgent,
    );

    const { uaMismatch, ipMismatch } = this.computeMismatch({
      bindUa,
      bindIp,
      reqIp,
      reqUa,
      tokenIp,
      tokenUa,
      sessIp,
      sessUa,
    });

    if (!uaMismatch && !ipMismatch) return;

    this.logFingerprintMismatch({
      userId: params.userId,
      jti: params.jti,
      sid: params.sid,
      bindUa,
      bindIp,
      ipMismatch,
      uaMismatch,
      tokenIp,
      sessIp,
      reqIp,
      tokenUa,
      sessUa,
      reqUa,
    });

    await this.applyFingerprintMismatchResponse({
      userId: params.userId,
      jti: params.jti,
      sid: params.sid,
    });

    this.logFingerprintMismatchApplied({
      userId: params.userId,
      jti: params.jti,
      sid: params.sid,
    });

    throw new UnauthorizedException('Токен відкликано або недійсний');
  }
  async getSaltForClaim(params: {
    userId: string;
    jti: string;
  }): Promise<string | null> {
    const row = await this.prisma.refreshToken.findFirst({
      where: { userId: params.userId, jti: params.jti },
      select: { tokenSalt: true },
    });

    return row?.tokenSalt ?? null;
  }
}
