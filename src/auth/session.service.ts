import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { normalizeIp } from 'src/common/helpers/ip-normalize';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class SessionService {
  constructor(private readonly prisma: PrismaService) {}

  async create(
    userId: string,
    refreshTokenId: string,
    ip?: string,
    userAgent?: string,
  ) {
    return this.prisma.session.create({
      data: {
        userId,
        refreshTokenId,
        ip: ip ? normalizeIp(ip) : null,
        userAgent: userAgent?.trim() || null,
      },
    });
  }

  async getUserSessions(userId: string) {
    return this.prisma.session.findMany({ where: { userId } });
  }

  async getActiveUserSessions(userId: string, take = 50) {
    return this.prisma.session.findMany({
      where: { userId, isActive: true },
      orderBy: { startedAt: 'desc' },
      take,
    });
  }

  async getAllUserSessions(userId: string) {
    return this.prisma.session.findMany({
      where: { userId },
      orderBy: { startedAt: 'desc' },
    });
  }

  private async terminateSessions(where: Prisma.SessionWhereInput) {
    return this.prisma.session.updateMany({
      where: {
        ...where,
        isActive: true,
      },
      data: {
        isActive: false,
        endedAt: new Date(),
      },
    });
  }

  async terminateSpecificSession(
    userId: string,
    ip: string,
    userAgent: string,
  ) {
    return this.terminateSessions({
      userId,
      ip: normalizeIp(ip),
      userAgent: userAgent.trim(),
    });
  }

  async terminateOtherSessions(userId: string, excludeSessionId: string) {
    return this.terminateSessions({
      userId,
      NOT: { id: excludeSessionId },
    });
  }

  async terminateAll(userId: string) {
    return this.terminateSessions({ userId });
  }

  async terminateByRefreshToken(jti: string) {
    return this.terminateSessions({
      refreshTokenId: jti,
    });
  }

  async countActive(userId: string): Promise<number> {
    return this.prisma.session.count({
      where: { userId, isActive: true },
    });
  }
}
