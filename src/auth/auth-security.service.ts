import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import { AppLogger } from 'src/logger/logger.service';
import { hashId, maskIp } from 'src/common/logging/log-sanitize';
import { normalizeIp } from 'src/common/net/ip-normalize';

function now() {
  return new Date();
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

  async assertNotLocked(userId: string) {
    const sec = await this.prisma.userSecurity.findUnique({
      where: { userId },
    });
    if (!sec?.lockedUntil) return;

    if (sec.lockedUntil.getTime() > Date.now()) {
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
  }

  async onLoginFailed(params: {
    userId: string;
    ip?: string | null;
    userAgent?: string | null;
  }) {
    const { maxAttempts, baseSec, maxSec, windowSec } = this.policy();
    const ts = now();

    const uaHash = params.userAgent ? hashId(params.userAgent) : undefined;
    const ipNorm = params.ip ? normalizeIp(params.ip) : null;
    const ipMasked = ipNorm ? maskIp(ipNorm) : undefined;

    const prev = await this.prisma.userSecurity.findUnique({
      where: { userId: params.userId },
      select: { failedLoginCount: true, lastFailedAt: true, lockedUntil: true },
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
      attempt >= maxAttempts ? new Date(ts.getTime() + delaySec * 1000) : null;

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

    if (lock) {
      this.logger.warn(
        'Account locked after failed logins',
        AuthSecurityService.name,
        {
          event: 'auth.lock.set',
          userId: params.userId,
          attempt,
          delaySec,
          ipMasked,
          uaHash,
          lockedUntil: lock.toISOString(),
        },
      );
    } else {
      this.logger.warn('Login failed recorded', AuthSecurityService.name, {
        event: 'auth.login.fail.recorded',
        userId: params.userId,
        attempt,
        delaySec,
        ipMasked,
        uaHash,
      });
    }

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
}
