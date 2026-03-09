import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AppLogger } from 'src/logger/logger.service';

@Injectable()
export class AuthMaintenanceService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(AuthMaintenanceService.name);
  }

  async cleanRevokedTokens(olderThanDays = 7): Promise<number> {
    const dateThreshold = new Date();
    dateThreshold.setDate(dateThreshold.getDate() - olderThanDays);

    this.logger.log(
      'Cleanup revoked tokens start',
      AuthMaintenanceService.name,
      {
        event: 'cleanup.refresh_tokens.start',
        olderThanDays,
        threshold: dateThreshold.toISOString(),
      },
    );

    const now = new Date();

    const deleted = await this.prisma.refreshToken.deleteMany({
      where: {
        OR: [
          { revoked: true, createdAt: { lt: dateThreshold } },
          { expiresAt: { lt: now } },
        ],
      },
    });

    this.logger.log(
      'Cleanup revoked tokens done',
      AuthMaintenanceService.name,
      {
        event: 'cleanup.refresh_tokens.done',
        olderThanDays,
        deleted: deleted.count,
      },
    );

    return deleted.count;
  }

  async cleanInactiveSessions(olderThanDays = 7): Promise<number> {
    const dateThreshold = new Date();
    dateThreshold.setDate(dateThreshold.getDate() - olderThanDays);

    this.logger.log(
      'Cleanup inactive sessions start',
      AuthMaintenanceService.name,
      {
        event: 'cleanup.sessions.start',
        olderThanDays,
        threshold: dateThreshold.toISOString(),
      },
    );

    const deleted = await this.prisma.session.deleteMany({
      where: {
        isActive: false,
        endedAt: { lt: dateThreshold },
      },
    });

    this.logger.log(
      'Cleanup inactive sessions done',
      AuthMaintenanceService.name,
      {
        event: 'cleanup.sessions.done',
        olderThanDays,
        deleted: deleted.count,
      },
    );

    return deleted.count;
  }

  async cleanLoginIdentifierSecurity(
    olderThanDays = 90,
    deleteLimit = 5000,
  ): Promise<number> {
    const now = new Date();
    const dateThreshold = new Date();
    dateThreshold.setDate(dateThreshold.getDate() - olderThanDays);

    this.logger.log(
      'Cleanup login identifier security start',
      AuthMaintenanceService.name,
      {
        event: 'cleanup.login_identifier_security.start',
        olderThanDays,
        deleteLimit,
        threshold: dateThreshold.toISOString(),
      },
    );

    const candidates = await this.prisma.loginIdentifierSecurity.findMany({
      where: {
        updatedAt: { lt: dateThreshold },
        AND: [
          {
            OR: [{ lockedUntil: null }, { lockedUntil: { lt: now } }],
          },
          {
            OR: [
              { lastFailedAt: null },
              { lastFailedAt: { lt: dateThreshold } },
            ],
          },
        ],
      },
      select: {
        emailHash: true,
      },
      orderBy: {
        updatedAt: 'asc',
      },
      take: deleteLimit,
    });

    if (candidates.length === 0) {
      this.logger.log(
        'Cleanup login identifier security done',
        AuthMaintenanceService.name,
        {
          event: 'cleanup.login_identifier_security.done',
          olderThanDays,
          deleteLimit,
          deleted: 0,
        },
      );

      return 0;
    }

    const deleted = await this.prisma.loginIdentifierSecurity.deleteMany({
      where: {
        emailHash: {
          in: candidates.map((item) => item.emailHash),
        },
      },
    });

    this.logger.log(
      'Cleanup login identifier security done',
      AuthMaintenanceService.name,
      {
        event: 'cleanup.login_identifier_security.done',
        olderThanDays,
        deleteLimit,
        deleted: deleted.count,
      },
    );

    return deleted.count;
  }
}
