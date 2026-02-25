import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { normalizeIp } from 'src/common/net/ip-normalize';
import { PrismaService } from 'src/prisma/prisma.service';
import { AppLogger } from 'src/logger/logger.service';
import { maskIp, hashId } from 'src/common/logging/log-sanitize';

@Injectable()
export class SessionRepositoryService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(SessionRepositoryService.name);
  }

  async create(
    sessionId: string,
    userId: string,
    refreshTokenJti: string,
    ip?: string,
    userAgent?: string,
    geo?: { country?: string; asn?: number; asOrgHash?: string },
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
        geoCountry: geo?.country ?? null,
        asn: geo?.asn ?? null,
        asOrgHash: geo?.asOrgHash ?? null,
      },
    });

    this.logger.log('Session created', SessionRepositoryService.name, {
      event: 'session.created',
      userId,
      sid: sessionId,
      jti: refreshTokenJti,
      ipMasked: nip ? maskIp(nip) : undefined,
      uaHash: ua ? hashId(ua) : undefined,
    });

    return session;
  }

  getUserSessions(userId: string) {
    return this.prisma.session.findMany({ where: { userId } });
  }

  async getActiveUserSessions(userId: string, take = 50) {
    const sessions = await this.prisma.session.findMany({
      where: { userId, isActive: true },
      orderBy: { startedAt: 'desc' },
      take,
    });

    this.logger.debug(
      'Active sessions fetched',
      SessionRepositoryService.name,
      {
        event: 'session.list.active',
        userId,
        take,
        returned: sessions.length,
      },
    );

    return sessions;
  }

  async getAllUserSessions(userId: string) {
    const sessions = await this.prisma.session.findMany({
      where: { userId },
      orderBy: { startedAt: 'desc' },
    });

    this.logger.debug('All sessions fetched', SessionRepositoryService.name, {
      event: 'session.list.all',
      userId,
      returned: sessions.length,
    });

    return sessions;
  }

  countActive(userId: string): Promise<number> {
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

  async getActiveSessionContext(params: {
    sid: string;
    userId: string;
  }): Promise<{
    refreshTokenJti: string | null;
    geoCountry: string | null;
    asn: number | null;
    asOrgHash: string | null;
  } | null> {
    const session = await this.prisma.session.findFirst({
      where: {
        id: params.sid,
        userId: params.userId,
        isActive: true,
        endedAt: null,
      },
      select: {
        refreshTokenJti: true,
        geoCountry: true,
        asn: true,
        asOrgHash: true,
      },
    });

    return session
      ? {
          refreshTokenJti: session.refreshTokenJti ?? null,
          geoCountry: session.geoCountry ?? null,
          asn: session.asn ?? null,
          asOrgHash: session.asOrgHash ?? null,
        }
      : null;
  }
}
