import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { normalizeIp } from 'src/common/net/ip-normalize';
import { PrismaService } from 'src/prisma/prisma.service';
import { AppLogger } from 'src/logger/logger.service';
import { maskIp, hashId } from 'src/common/logging/log-sanitize';

@Injectable()
export class RefreshBindingService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(RefreshBindingService.name);
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
        RefreshBindingService.name,
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
        RefreshBindingService.name,
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
}
