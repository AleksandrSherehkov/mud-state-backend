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
    userId: string,
    refreshTokenId: string,
    ip?: string,
    userAgent?: string,
  ) {
    const nip = ip ? normalizeIp(ip) : null;
    const ua = userAgent?.trim() || null;

    const session = await this.prisma.session.create({
      data: {
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
  ) {
    const result = await this.prisma.session.updateMany({
      where: {
        ...where,
        isActive: true,
      },
      data: {
        isActive: false,
        endedAt: new Date(),
      },
    });

    if (result.count > 0) {
      this.logger.log('Sessions terminated', SessionService.name, {
        event: 'session.terminated',
        count: result.count,
        ...meta,
      });
    } else {
      this.logger.debug(
        'Terminate sessions: nothing to terminate',
        SessionService.name,
        {
          event: 'session.terminate.noop',
          ...meta,
        },
      );
    }

    return result;
  }

  async terminateSpecificSession(
    userId: string,
    ip: string,
    userAgent: string,
  ) {
    const nip = normalizeIp(ip);
    const ua = userAgent.trim();

    return this.terminateSessions(
      {
        userId,
        ip: nip,
        userAgent: ua,
      },
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
      {
        userId,
        NOT: { id: excludeSessionId },
      },
      {
        userId,
        excludeSid: excludeSessionId,
        reason: 'others',
      },
    );
  }

  async terminateAll(userId: string) {
    return this.terminateSessions(
      { userId },
      {
        userId,
        reason: 'all',
      },
    );
  }

  async terminateByRefreshToken(jti: string) {
    return this.terminateSessions(
      { refreshTokenId: jti },
      {
        jti,
        reason: 'by_refresh_token',
      },
    );
  }

  async countActive(userId: string): Promise<number> {
    return this.prisma.session.count({
      where: { userId, isActive: true },
    });
  }
}
