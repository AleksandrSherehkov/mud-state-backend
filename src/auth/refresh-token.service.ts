import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AppLogger } from 'src/logger/logger.service';
import { maskIp, hashId } from 'src/common/helpers/log-sanitize';
import { Prisma } from '@prisma/client';
import { normalizeIp } from 'src/common/helpers/ip-normalize';

@Injectable()
export class RefreshTokenService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(RefreshTokenService.name);
  }

  async create(
    userId: string,
    jti: string,
    tokenHash: string,
    ip?: string,
    userAgent?: string,
    tx?: Prisma.TransactionClient,
  ) {
    const db = tx ?? this.prisma;

    const nip = ip ? normalizeIp(ip) : undefined;
    const ua = userAgent?.trim() || undefined;

    const token = await db.refreshToken.create({
      data: {
        userId,
        jti,
        tokenHash,
        ip: nip,
        userAgent: ua,
      },
    });

    this.logger.log('Refresh token created', RefreshTokenService.name, {
      event: 'refresh_token.created',
      userId,
      jti,
      ipMasked: nip ? maskIp(nip) : undefined,
      uaHash: ua ? hashId(ua) : undefined,
    });

    return token;
  }

  async getActiveTokens(userId: string, take = 50) {
    const tokens = await this.prisma.refreshToken.findMany({
      where: { userId, revoked: false },
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
      where: { userId, jti, revoked: false },
    });
  }

  async countActive(userId: string) {
    return this.prisma.refreshToken.count({
      where: { userId, revoked: false },
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
  async assertFingerprint(params: {
    userId: string;
    jti: string;
    sid: string;
    ip?: string | null;
    userAgent?: string | null;
  }) {
    const token = await this.prisma.refreshToken.findFirst({
      where: { userId: params.userId, jti: params.jti, revoked: false },
      select: { ip: true, userAgent: true },
    });

    const session = await this.prisma.session.findFirst({
      where: {
        id: params.sid,
        userId: params.userId,
        isActive: true,
        endedAt: null,
      },
      select: { ip: true, userAgent: true },
    });

    if (!token || !session) {
      throw new UnauthorizedException('Токен відкликано або недійсний');
    }

    const reqIp = params.ip ?? null;
    const reqUa = (params.userAgent ?? '').trim() || null;

    const tokenIp = token.ip ?? null;
    const tokenUa = (token.userAgent ?? '').trim() || null;

    const sessIp = session.ip ?? null;
    const sessUa = (session.userAgent ?? '').trim() || null;

    // ---- политика (по умолчанию UA-only) ----
    // UA mismatch => блок
    const uaMismatch =
      (!!tokenUa && !!reqUa && tokenUa !== reqUa) ||
      (!!sessUa && !!reqUa && sessUa !== reqUa);

    const ipMismatch =
      (!!tokenIp && !!reqIp && tokenIp !== reqIp) ||
      (!!sessIp && !!reqIp && sessIp !== reqIp);

    if (uaMismatch || ipMismatch) {
      this.logger.warn(
        'Refresh fingerprint mismatch',
        RefreshTokenService.name,
        {
          event: 'auth.refresh.fingerprint_mismatch',
          userId: params.userId,
          jti: params.jti,
          sid: params.sid,
          ipMismatch,
          uaMismatch,
          tokenIpMasked: tokenIp ? maskIp(tokenIp) : undefined,
          sessionIpMasked: sessIp ? maskIp(sessIp) : undefined,
          reqIpMasked: reqIp ? maskIp(reqIp) : undefined,
          tokenUaHash: tokenUa ? hashId(tokenUa) : undefined,
          sessionUaHash: sessUa ? hashId(sessUa) : undefined,
          reqUaHash: reqUa ? hashId(reqUa) : undefined,
        },
      );

      await Promise.all([
        this.prisma.refreshToken.updateMany({
          where: { userId: params.userId, revoked: false },
          data: { revoked: true },
        }),
        this.prisma.session.updateMany({
          where: { userId: params.userId, isActive: true },
          data: { isActive: false, endedAt: new Date() },
        }),
      ]);

      throw new UnauthorizedException('Токен відкликано або недійсний');
    }
  }
}
