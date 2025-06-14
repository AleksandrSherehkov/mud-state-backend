import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class SessionService {
  constructor(private prisma: PrismaService) {}

  async create(
    userId: string,
    refreshTokenId: string,
    ip?: string,
    userAgent?: string,
  ) {
    return this.prisma.session.create({
      data: { userId, refreshTokenId, ip, userAgent },
    });
  }

  async getUserSessions(userId: string) {
    return this.prisma.session.findMany({ where: { userId } });
  }

  async getActiveUserSessions(userId: string) {
    return this.prisma.session.findMany({
      where: { userId, isActive: true },
    });
  }

  async getAllUserSessions(userId: string) {
    return this.prisma.session.findMany({
      where: { userId },
      orderBy: { startedAt: 'desc' },
    });
  }

  async terminateSpecificSession(
    userId: string,
    ip: string,
    userAgent: string,
  ) {
    return this.prisma.session.updateMany({
      where: {
        userId,
        ip,
        userAgent,
        isActive: true,
      },
      data: {
        isActive: false,
        endedAt: new Date(),
      },
    });
  }

  async terminateOtherSessions(userId: string, excludeSessionId: string) {
    return this.prisma.session.updateMany({
      where: {
        userId,
        isActive: true,
        NOT: { id: excludeSessionId },
      },
      data: {
        isActive: false,
        endedAt: new Date(),
      },
    });
  }

  async terminateAll(userId: string) {
    return this.prisma.session.updateMany({
      where: { userId, isActive: true },
      data: { isActive: false, endedAt: new Date() },
    });
  }

  async terminateByRefreshToken(jti: string) {
    return this.prisma.session.updateMany({
      where: { refreshTokenId: jti, endedAt: null },
      data: { endedAt: new Date(), isActive: false },
    });
  }

  async countActive(userId: string): Promise<number> {
    return this.prisma.session.count({
      where: { userId, isActive: true },
    });
  }
}
