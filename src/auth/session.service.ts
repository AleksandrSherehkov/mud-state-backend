import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { normalizeIp } from 'src/common/helpers/ip-normalize';
import { PrismaService } from 'src/prisma/prisma.service';
import { AppLogger } from 'src/logger/logger.service';
import { maskIp, hashId } from 'src/common/helpers/log-sanitize';

@Injectable()
export class SessionService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(SessionService.name);
  }

  async create(
    sessionId: string,
    userId: string,
    refreshTokenId: string,
    ip?: string,
    userAgent?: string,
  ) {
    const nip = ip ? normalizeIp(ip) : null;
    const ua = userAgent?.trim() || null;

    const session = await this.prisma.session.create({
      data: {
        id: sessionId,
        userId,
        refreshTokenId,
        ip: nip,
        userAgent: ua,
      },
    });

    this.logger.log('Session created', SessionService.name, {
      event: 'session.created',
      userId,
      sid: session.id,
      jti: refreshTokenId,
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

    this.logger.debug('Active sessions fetched', SessionService.name, {
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

    this.logger.debug('All sessions fetched', SessionService.name, {
      event: 'session.list.all',
      userId,
      returned: sessions.length,
    });

    return sessions;
  }

  private async terminateSessions(
    where: Prisma.SessionWhereInput,
    meta: Record<string, unknown>,
  ): Promise<Prisma.BatchPayload> {
    const sessions = await this.prisma.session.findMany({
      where: { ...where, isActive: true },
      select: { id: true, refreshTokenId: true },
    });

    if (sessions.length === 0) {
      this.logger.debug(
        'Terminate sessions: nothing to terminate',
        SessionService.name,
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
          .map((s) => s.refreshTokenId)
          .filter((x): x is string => !!x)
          .map((x) => x.trim()),
      ),
    ];

    const { revoked, terminated } = await this.prisma.$transaction(
      async (tx) => {
        const revoked = jtis.length
          ? await tx.refreshToken.updateMany({
              where: { jti: { in: jtis }, revoked: false },
              data: { revoked: true },
            })
          : ({ count: 0 } as Prisma.BatchPayload);

        const terminated = await tx.session.updateMany({
          where: { id: { in: sessionIds }, isActive: true },
          data: { isActive: false, endedAt: now },
        });

        return { revoked, terminated };
      },
    );

    this.logger.log('Sessions terminated', SessionService.name, {
      event: 'session.terminated',
      count: terminated.count,
      revokedRefreshCount: revoked.count,
      sessionsMatched: sessions.length,
      jtisMatched: jtis.length,
      ...meta,
    });

    if (jtis.length === 0) {
      this.logger.debug(
        'Terminate sessions: no JTIs to revoke',
        SessionService.name,
        {
          event: 'session.terminated.no_jti',
          ...meta,
        },
      );
    } else if (revoked.count === 0) {
      this.logger.debug(
        'Terminate sessions: refresh revoke noop',
        SessionService.name,
        {
          event: 'refresh_token.revoke_many.noop',
          jtisMatched: jtis.length,
          ...meta,
        },
      );
    }

    return terminated;
  }

  async terminateSpecificSession(
    userId: string,
    ip: string,
    userAgent: string,
  ) {
    const nip = normalizeIp(ip);
    const ua = userAgent.trim();

    return this.terminateSessions(
      { userId, ip: nip, userAgent: ua },
      {
        userId,
        ipMasked: maskIp(nip),
        uaHash: hashId(ua),
        reason: 'specific',
      },
    );
  }

  async terminateOtherSessions(userId: string, excludeSessionId: string) {
    return this.terminateSessions(
      { userId, NOT: { id: excludeSessionId } },
      { userId, excludeSid: excludeSessionId, reason: 'others' },
    );
  }

  async terminateAll(userId: string) {
    return this.terminateSessions({ userId }, { userId, reason: 'all' });
  }

  async terminateByRefreshToken(jti: string) {
    return this.terminateSessions(
      { refreshTokenId: jti },
      { jti, reason: 'by_refresh_token' },
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
  async isSessionActiveById(sessionId: string): Promise<boolean> {
    const session = await this.prisma.session.findFirst({
      where: { id: sessionId, isActive: true, endedAt: null },
      select: { id: true },
    });
    return !!session;
  }
}
