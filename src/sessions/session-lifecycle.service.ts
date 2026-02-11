import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { AppLogger } from 'src/logger/logger.service';

type LifecycleReason =
  | 'logout'
  | 'refresh_reuse_detected'
  | 'fingerprint_mismatch'
  | 'admin_terminate'
  | 'security_policy';

@Injectable()
export class SessionLifecycleService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(SessionLifecycleService.name);
  }

  private now(): Date {
    return new Date();
  }

  async revokeAllAndTerminateAll(params: {
    userId: string;
    reason: LifecycleReason;
    tx?: Prisma.TransactionClient;
  }): Promise<{ revokedTokens: number; terminatedSessions: number }> {
    const db = params.tx ?? this.prisma;
    const ts = this.now();

    const [revoked, terminated] = await Promise.all([
      db.refreshToken.updateMany({
        where: { userId: params.userId, revoked: false },
        data: { revoked: true },
      }),
      db.session.updateMany({
        where: { userId: params.userId, isActive: true, endedAt: null },
        data: { isActive: false, endedAt: ts },
      }),
    ]);

    this.logger.warn(
      'Lifecycle applied: revoke all + terminate all',
      undefined,
      {
        event: 'lifecycle.user_wide_applied',
        userId: params.userId,
        reason: params.reason,
        revokedTokens: revoked.count,
        terminatedSessions: terminated.count,
      },
    );

    return {
      revokedTokens: revoked.count,
      terminatedSessions: terminated.count,
    };
  }

  async revokeJtiAndTerminateSession(params: {
    userId: string;
    jti: string;
    sid: string;
    reason: LifecycleReason;
    tx?: Prisma.TransactionClient;
  }): Promise<{ revokedTokens: number; terminatedSessions: number }> {
    const db = params.tx ?? this.prisma;
    const ts = this.now();

    const [revoked, terminated] = await Promise.all([
      db.refreshToken.updateMany({
        where: {
          userId: params.userId,
          jti: params.jti,
          revoked: false,
        },
        data: { revoked: true },
      }),
      db.session.updateMany({
        where: {
          id: params.sid,
          userId: params.userId,
          isActive: true,
          endedAt: null,
        },
        data: { isActive: false, endedAt: ts },
      }),
    ]);

    this.logger.warn(
      'Lifecycle applied: revoke jti + terminate sid',
      undefined,
      {
        event: 'lifecycle.scoped_applied',
        userId: params.userId,
        reason: params.reason,
        jti: params.jti,
        sid: params.sid,
        revokedTokens: revoked.count,
        terminatedSessions: terminated.count,
      },
    );

    return {
      revokedTokens: revoked.count,
      terminatedSessions: terminated.count,
    };
  }
}
