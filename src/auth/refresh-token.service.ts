import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AppLogger } from 'src/logger/logger.service';
import { maskIp, hashId } from 'src/common/helpers/log-sanitize';

@Injectable()
export class RefreshTokenService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(RefreshTokenService.name);
  }

  async create(userId: string, jti: string, ip?: string, userAgent?: string) {
    const token = await this.prisma.refreshToken.create({
      data: { userId, jti, ip, userAgent },
    });

    this.logger.log('Refresh token created', RefreshTokenService.name, {
      event: 'refresh_token.created',
      userId,
      jti,
      ipMasked: ip ? maskIp(ip) : undefined,
      uaHash: userAgent ? hashId(userAgent.trim()) : undefined,
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

  async revokeIfActive(jti: string, userId: string) {
    const result = await this.prisma.refreshToken.updateMany({
      where: { jti, userId, revoked: false },
      data: { revoked: true },
    });

    if (result.count === 1) {
      this.logger.log('Refresh token claimed', RefreshTokenService.name, {
        event: 'refresh_token.claimed',
        userId,
        jti,
      });
    } else {
      this.logger.warn(
        'Refresh token claim failed (revoked/reuse/mismatch)',
        RefreshTokenService.name,
        {
          event: 'refresh_token.claim_failed',
          userId,
          jti,
          count: result.count,
        },
      );
    }

    return result;
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
}
