import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import { AppLogger } from 'src/logger/logger.service';
import { hashId, maskIp } from 'src/common/helpers/log-sanitize';
import { normalizeIp } from 'src/common/helpers/ip-normalize';

function now() {
  return new Date();
}

function getSubnetKey(ip: string): string {
  if (ip.includes('.')) {
    const parts = ip.split('.');
    if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }

  if (ip.includes(':')) {
    const parts = ip.split(':').filter(Boolean);
    const prefix = parts.slice(0, 4).join(':') || '::';
    return `${prefix}::/64`;
  }

  return 'unknown';
}

@Injectable()
export class AuthSecurityService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(AuthSecurityService.name);
  }

  private policy() {
    return {
      maxAttempts: Number(this.config.get('AUTH_LOCK_MAX_ATTEMPTS') ?? 10),
      baseSec: Number(this.config.get('AUTH_LOCK_BASE_SECONDS') ?? 2),
      maxSec: Number(this.config.get('AUTH_LOCK_MAX_SECONDS') ?? 300),
      windowSec: Number(this.config.get('AUTH_LOCK_WINDOW_SECONDS') ?? 900),
    };
  }

  async assertNotLocked(userId: string, ip?: string | null) {
    const sec = await this.prisma.userSecurity.findUnique({
      where: { userId },
    });

    if (sec?.lockedUntil && sec.lockedUntil.getTime() > Date.now()) {
      this.logger.warn(
        'Login blocked: account locked',
        AuthSecurityService.name,
        {
          event: 'auth.lock.block',
          userId,
          lockedUntil: sec.lockedUntil.toISOString(),
        },
      );

      throw new UnauthorizedException('Невірний email або пароль');
    }

    if (!ip) return;

    const ipNorm = normalizeIp(ip);
    const keys = [`ip:${ipNorm}`, `subnet:${getSubnetKey(ipNorm)}`];

    const rows = await this.prisma.loginAbuseCounter.findMany({
      where: {
        key: { in: keys },
        lockedUntil: { gt: now() },
      },
      select: { key: true, lockedUntil: true },
    });

    if (rows.length > 0) {
      this.logger.warn(
        'Login blocked: network lock',
        AuthSecurityService.name,
        {
          event: 'auth.lock.block_network',
          userId,
          ipMasked: maskIp(ipNorm),
          keys: rows.map((r) => r.key),
        },
      );

      throw new UnauthorizedException('Невірний email або пароль');
    }
  }

  async onLoginFailed(params: {
    userId?: string;
    ip?: string | null;
    userAgent?: string | null;
  }) {
    const { maxAttempts, baseSec, maxSec, windowSec } = this.policy();
    const ts = now();

    const uaHash = params.userAgent ? hashId(params.userAgent) : undefined;
    const ipNorm = params.ip ? normalizeIp(params.ip) : null;
    const ipMasked = ipNorm ? maskIp(ipNorm) : undefined;

    if (params.userId) {
      const prev = await this.prisma.userSecurity.findUnique({
        where: { userId: params.userId },
        select: {
          failedLoginCount: true,
          lastFailedAt: true,
          lockedUntil: true,
        },
      });

      const windowExpired =
        !prev?.lastFailedAt ||
        (ts.getTime() - prev.lastFailedAt.getTime()) / 1000 > windowSec;

      const nextCount = windowExpired ? 1 : (prev?.failedLoginCount ?? 0) + 1;
      const attempt = Math.min(nextCount, 30);

      const delaySec = Math.min(
        maxSec,
        baseSec * Math.pow(2, Math.max(0, attempt - 1)),
      );

      const lock =
        attempt >= maxAttempts
          ? new Date(ts.getTime() + delaySec * 1000)
          : null;

      await this.prisma.userSecurity.upsert({
        where: { userId: params.userId },
        create: {
          userId: params.userId,
          failedLoginCount: 1,
          lastFailedAt: ts,
          lockedUntil: lock,
          lastFailedIp: ipNorm,
          lastFailedUaHash: uaHash ?? null,
        },
        update: {
          failedLoginCount: nextCount,
          lastFailedAt: ts,
          lockedUntil: lock,
          lastFailedIp: ipNorm,
          lastFailedUaHash: uaHash ?? null,
        },
      });
    }

    if (ipNorm) {
      await this.recordNetworkFailure({
        key: `ip:${ipNorm}`,
        kind: 'ip',
        ts,
        windowSec,
        maxAttempts,
        baseSec,
        maxSec,
      });
      await this.recordNetworkFailure({
        key: `subnet:${getSubnetKey(ipNorm)}`,
        kind: 'subnet',
        ts,
        windowSec,
        maxAttempts: Math.max(maxAttempts * 2, 20),
        baseSec,
        maxSec,
      });
    }

    this.logger.warn('Login failed recorded', AuthSecurityService.name, {
      event: 'auth.login.fail.recorded',
      userId: params.userId,
      ipMasked,
      uaHash,
    });

    throw new UnauthorizedException('Невірний email або пароль');
  }

  async onLoginSuccess(userId: string) {
    await this.prisma.userSecurity.upsert({
      where: { userId },
      create: {
        userId,
        failedLoginCount: 0,
        lockedUntil: null,
        lastFailedAt: null,
      },
      update: { failedLoginCount: 0, lockedUntil: null, lastFailedAt: null },
    });

    this.logger.debug(
      'Login security counters reset',
      AuthSecurityService.name,
      {
        event: 'auth.lock.reset',
        userId,
      },
    );
  }

  private async recordNetworkFailure(params: {
    key: string;
    kind: string;
    ts: Date;
    windowSec: number;
    maxAttempts: number;
    baseSec: number;
    maxSec: number;
  }): Promise<void> {
    const prev = await this.prisma.loginAbuseCounter.findUnique({
      where: { key: params.key },
      select: { failedCount: true, lastFailedAt: true },
    });

    const windowExpired =
      !prev?.lastFailedAt ||
      (params.ts.getTime() - prev.lastFailedAt.getTime()) / 1000 >
        params.windowSec;

    const nextCount = windowExpired ? 1 : (prev?.failedCount ?? 0) + 1;
    const attempt = Math.min(nextCount, 30);
    const delaySec = Math.min(
      params.maxSec,
      params.baseSec * Math.pow(2, Math.max(0, attempt - 1)),
    );

    const lock =
      attempt >= params.maxAttempts
        ? new Date(params.ts.getTime() + delaySec * 1000)
        : null;

    await this.prisma.loginAbuseCounter.upsert({
      where: { key: params.key },
      create: {
        key: params.key,
        kind: params.kind,
        failedCount: nextCount,
        lastFailedAt: params.ts,
        windowStartedAt: params.ts,
        lockedUntil: lock,
      },
      update: {
        failedCount: nextCount,
        kind: params.kind,
        lastFailedAt: params.ts,
        windowStartedAt: params.ts,
        lockedUntil: lock,
      },
    });
  }
}
