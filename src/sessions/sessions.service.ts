import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { normalizeIp } from 'src/common/helpers/ip-normalize';
import { PrismaService } from 'src/prisma/prisma.service';
import { AppLogger } from 'src/logger/logger.service';
import { maskIp, hashId } from 'src/common/helpers/log-sanitize';
import { RefreshTokenService } from './refresh-token.service';

@Injectable()
export class SessionsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly logger: AppLogger,
    private readonly refreshTokenService: RefreshTokenService,
  ) {
    this.logger.setContext(SessionsService.name);
  }

  async create(
    sessionId: string,
    userId: string,
    refreshTokenJti: string,
    ip?: string,
    userAgent?: string,
    tx?: Prisma.TransactionClient,
  ) {
    const nip = ip ? normalizeIp(ip) : null;
    const ua = userAgent?.trim() || null;

    const db = tx ?? this.prisma;

    const session = await db.session.create({
      data: {
        id: sessionId,
        userId,
        refreshTokenJti,
        ip: nip,
        userAgent: ua,
      },
    });

    this.logger.log('Session created', SessionsService.name, {
      event: 'session.created',
      userId,
      sid: sessionId,
      jti: refreshTokenJti,
      ipMasked: nip ? maskIp(nip) : undefined,
      uaHash: ua ? hashId(ua) : undefined,
    });

    return session;
  }

  async getUserSessions(userId: string) {
    return this.prisma.session.findMany({ where: { userId } });
  }

  async getActiveUserSessions(userId: string, take = 50) {
    const sessions = await this.prisma.session.findMany({
      where: { userId, isActive: true },
      orderBy: { startedAt: 'desc' },
      take,
    });

    this.logger.debug('Active sessions fetched', SessionsService.name, {
      event: 'session.list.active',
      userId,
      take,
      returned: sessions.length,
    });

    return sessions;
  }

  async getAllUserSessions(userId: string) {
    const sessions = await this.prisma.session.findMany({
      where: { userId },
      orderBy: { startedAt: 'desc' },
    });

    this.logger.debug('All sessions fetched', SessionsService.name, {
      event: 'session.list.all',
      userId,
      returned: sessions.length,
    });

    return sessions;
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
      this.logger.debug('Session cap ok (no eviction)', SessionsService.name, {
        event: 'session.cap.noop',
        userId,
        maxActive: max,
        keepBeforeCreate: keep,
        active: active.length,
        ...(meta ?? undefined),
      });
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
        SessionsService.name,
        {
          event: 'session.terminate.noop',
          ...meta,
        },
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

    this.logger.log('Sessions terminated', SessionsService.name, {
      event: 'session.terminated',
      count: terminated.count,
      revokedRefreshCount: revoked.count,
      sessionsMatched: sessions.length,
      jtisMatched: jtis.length,
      ...meta,
    });

    return terminated;
  }

  async terminateOtherSessions(userId: string, excludeSessionId: string) {
    return this.prisma.$transaction((tx) =>
      this.terminateSessions(
        { userId, NOT: { id: excludeSessionId } },
        { userId, excludeSid: excludeSessionId, reason: 'others' },
        tx,
      ),
    );
  }

  async terminateAll(userId: string) {
    return this.prisma.$transaction((tx) =>
      this.terminateSessions({ userId }, { userId, reason: 'all' }, tx),
    );
  }

  async terminateByRefreshToken(jti: string) {
    return this.prisma.$transaction((tx) =>
      this.terminateSessions(
        { refreshTokenJti: jti },
        { jti, reason: 'by_refresh_token' },
        tx,
      ),
    );
  }

  async countActive(userId: string): Promise<number> {
    return this.prisma.session.count({ where: { userId, isActive: true } });
  }

  async isSessionActive(sessionId: string, userId: string): Promise<boolean> {
    const session = await this.prisma.session.findFirst({
      where: { id: sessionId, userId, isActive: true, endedAt: null },
      select: { id: true },
    });
    return !!session;
  }
  async getActiveSessionBinding(params: {
    sid: string;
    userId: string;
  }): Promise<{ refreshTokenJti: string | null } | null> {
    const session = await this.prisma.session.findFirst({
      where: {
        id: params.sid,
        userId: params.userId,
        isActive: true,
        endedAt: null,
      },
      select: { refreshTokenJti: true },
    });

    return session
      ? { refreshTokenJti: session.refreshTokenJti ?? null }
      : null;
  }

  async isSessionActiveById(sessionId: string): Promise<boolean> {
    const session = await this.prisma.session.findFirst({
      where: { id: sessionId, isActive: true, endedAt: null },
      select: { id: true },
    });
    return !!session;
  }
  async updateRefreshBinding(params: {
    sid: string;
    userId: string;
    newJti: string;
    ip?: string | null;
    userAgent?: string | null;
    tx?: Prisma.TransactionClient;
  }): Promise<number> {
    const db = params.tx ?? this.prisma;

    const nip = params.ip ? normalizeIp(params.ip) : null;
    const ua = (params.userAgent ?? '').trim() || null;

    const updated = await db.session.updateMany({
      where: {
        id: params.sid,
        userId: params.userId,
        isActive: true,
        endedAt: null,
      },
      data: {
        refreshTokenJti: params.newJti,

        ip: nip,
        userAgent: ua,
      },
    });

    if (updated.count === 0) {
      this.logger.warn(
        'Session refresh binding update failed (session inactive or missing)',
        SessionsService.name,
        {
          event: 'session.refresh_binding.update_failed',
          userId: params.userId,
          sid: params.sid,
          newJti: params.newJti,
          ipMasked: nip ? maskIp(nip) : undefined,
          uaHash: ua ? hashId(ua) : undefined,
        },
      );
    } else {
      this.logger.debug(
        'Session refresh binding updated',
        SessionsService.name,
        {
          event: 'session.refresh_binding.updated',
          userId: params.userId,
          sid: params.sid,
          newJti: params.newJti,
        },
      );
    }
    return updated.count;
  }

  async terminateById(params: {
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
}
