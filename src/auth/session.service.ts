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
