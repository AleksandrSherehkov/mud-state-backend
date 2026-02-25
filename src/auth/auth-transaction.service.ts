import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Prisma } from '@prisma/client';

import { PrismaService } from 'src/prisma/prisma.service';
import { AppLogger } from 'src/logger/logger.service';

export type AuthTxRunOptions = {
  name?: string;
  maxWaitMs?: number;
  timeoutMs?: number;

  retries?: number;
  retryDelayMs?: number;
};

@Injectable()
export class AuthTransactionService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(AuthTransactionService.name);
  }

  private defaultMaxWaitMs(): number {
    return Number(this.config.get('AUTH_TX_MAX_WAIT_MS') ?? 2000);
  }

  private defaultTimeoutMs(): number {
    return Number(this.config.get('AUTH_TX_TIMEOUT_MS') ?? 5000);
  }

  private isTransientTxError(err: unknown): boolean {
    if (err instanceof Prisma.PrismaClientKnownRequestError) {
      if (err.code === 'P2028') return true;
    }

    const msg = err instanceof Error ? err.message : String(err);
    return /P2028|Transaction API error|timed out|timeout|already closed/i.test(
      msg,
    );
  }

  private async sleep(ms: number): Promise<void> {
    if (!ms) return;
    await new Promise((r) => setTimeout(r, ms));
  }

  async run<T>(
    fn: (tx: Prisma.TransactionClient) => Promise<T>,
    opts: AuthTxRunOptions = {},
  ): Promise<T> {
    const name = (opts.name ?? 'auth.tx').trim();

    const maxWait = Number(opts.maxWaitMs ?? this.defaultMaxWaitMs());
    const timeout = Number(opts.timeoutMs ?? this.defaultTimeoutMs());

    const retries = Math.max(0, Number(opts.retries ?? 0));
    const retryDelayMs = Math.max(0, Number(opts.retryDelayMs ?? 0));

    const txOptions: { maxWait: number; timeout: number } = {
      maxWait,
      timeout,
    };

    let attempt = 0;

    while (true) {
      try {
        attempt += 1;
        return await this.prisma.$transaction(async (tx) => fn(tx), txOptions);
      } catch (err: unknown) {
        const transient = this.isTransientTxError(err);

        this.logger.warn(
          'Auth transaction failed',
          AuthTransactionService.name,
          {
            event: 'auth.tx.fail',
            name,
            attempt,
            maxWait,
            timeout,
            transient,
            errorName: err instanceof Error ? err.name : 'UnknownError',
          },
        );

        if (transient && attempt <= retries + 1) {
          await this.sleep(retryDelayMs);
          continue;
        }

        if (transient) {
          throw new ServiceUnavailableException(
            'Сервіс тимчасово недоступний. Спробуйте ще раз.',
          );
        }

        throw err;
      }
    }
  }
}
