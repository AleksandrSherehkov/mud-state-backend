import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class RefreshTokenService {
  constructor(private prisma: PrismaService) {}

  async create(userId: string, jti: string, ip?: string, userAgent?: string) {
    return this.prisma.refreshToken.create({
      data: { userId, jti, ip, userAgent },
    });
  }

  async revokeAll(userId: string) {
    return this.prisma.refreshToken.updateMany({
      where: { userId, revoked: false },
      data: { revoked: true },
    });
  }

  async revokeByJti(jti: string) {
    return this.prisma.refreshToken.update({
      where: { jti },
      data: { revoked: true },
    });
  }

  async validate(jti: string, userId: string) {
    const token = await this.prisma.refreshToken.findUnique({ where: { jti } });
    if (!token || token.revoked || token.userId !== userId) {
      throw new UnauthorizedException('Токен відкликано або недійсний');
    }
  }

  async countActive(userId: string) {
    return this.prisma.refreshToken.count({
      where: { userId, revoked: false },
    });
  }
}
