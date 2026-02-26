import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from 'src/prisma/prisma.service';
import { AppLogger } from 'src/logger/logger.service';
import { RefreshTokenService } from './refresh-token.service';

@Injectable()
export class SessionTerminationService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly logger: AppLogger,
    private readonly refreshTokenService: RefreshTokenService,
  ) {
    this.logger.setContext(SessionTerminationService.name);
  }

  async enforceMaxActiveSessions(params: {
    userId: string;
    maxActive: number;
    meta?: Record<string, unknown>;
    tx: Prisma.TransactionClient;
  }): Promise<{ terminated: number }> {
    const { userId, maxActive, meta, tx } = params;

    const max = Number.isFinite(maxActive) ? Math.floor(maxActive) : 0;
    if (max <= 0) return { terminated: 0 };

    const keep = Math.max(0, max - 1);

    const active = await tx.session.findMany({
      where: { userId, isActive: true, endedAt: null },
      orderBy: { startedAt: 'desc' },
      select: { id: true },
    });

    if (active.length <= keep) {
      this.logger.debug(
        'Session cap ok (no eviction)',
        SessionTerminationService.name,
        {
          event: 'session.cap.noop',
          userId,
          maxActive: max,
          keepBeforeCreate: keep,
          active: active.length,
          ...(meta ?? undefined),
        },
      );
      return { terminated: 0 };
    }

    const toTerminateIds = active.slice(keep).map((s) => s.id);

    const terminated = await this.terminateSessions(
      { userId, id: { in: toTerminateIds } },
      {
        userId,
        reason: 'cap_evict_oldest',
        maxActive: max,
        keepBeforeCreate: keep,
        active: active.length,
        evicted: toTerminateIds.length,
        ...(meta ?? undefined),
      },
      tx,
    );

    return { terminated: terminated.count };
  }

  terminateOtherSessions(userId: string, excludeSessionId: string) {
    return this.prisma.$transaction((tx) =>
      this.terminateSessions(
        { userId, NOT: { id: excludeSessionId } },
        { userId, excludeSid: excludeSessionId, reason: 'others' },
        tx,
      ),
    );
  }

  terminateAll(userId: string) {
    return this.prisma.$transaction((tx) =>
      this.terminateSessions({ userId }, { userId, reason: 'all' }, tx),
    );
  }

  terminateByRefreshToken(jti: string) {
    return this.prisma.$transaction((tx) =>
      this.terminateSessions(
        { refreshTokenJti: jti },
        { jti, reason: 'by_refresh_token' },
        tx,
      ),
    );
  }

  terminateById(params: {
    sid: string;
    userId: string;
    reason?: string;
  }): Promise<Prisma.BatchPayload> {
    return this.prisma.$transaction((tx) =>
      this.terminateSessions(
        { id: params.sid, userId: params.userId },
        {
          userId: params.userId,
          sid: params.sid,
          reason: params.reason ?? 'by_sid',
        },
        tx,
      ),
    );
  }

  private async terminateSessions(
    where: Prisma.SessionWhereInput,
    meta: Record<string, unknown>,
    tx: Prisma.TransactionClient,
  ): Promise<Prisma.BatchPayload> {
    const sessions = await tx.session.findMany({
      where: { ...where, isActive: true, endedAt: null },
      select: { id: true, refreshTokenJti: true },
    });

    if (sessions.length === 0) {
      this.logger.debug(
        'Terminate sessions: nothing to terminate',
        SessionTerminationService.name,
        { event: 'session.terminate.noop', ...meta },
      );
      return { count: 0 };
    }

    const now = new Date();
    const sessionIds = sessions.map((s) => s.id);

    const jtis = [
      ...new Set(
        sessions
          .map((s) => s.refreshTokenJti)
          .filter((x): x is string => !!x)
          .map((x) => x.trim())
          .filter(Boolean),
      ),
    ];

    const revoked = jtis.length
      ? await this.refreshTokenService.revokeManyByJtis(jtis, meta, tx)
      : ({ count: 0 } as Prisma.BatchPayload);

    const terminated = await tx.session.updateMany({
      where: { id: { in: sessionIds }, isActive: true, endedAt: null },
      data: { isActive: false, endedAt: now },
    });

    this.logger.log('Sessions terminated', SessionTerminationService.name, {
      event: 'session.terminated',
      count: terminated.count,
      revokedRefreshCount: revoked.count,
      sessionsMatched: sessions.length,
      jtisMatched: jtis.length,
      ...meta,
    });

    return terminated;
  }
}
