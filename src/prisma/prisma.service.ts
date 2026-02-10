import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { Prisma, PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { AppLogger } from 'src/logger/logger.service';
import * as crypto from 'node:crypto';

function errMeta(err: unknown) {
  if (err instanceof Error)
    return { errorName: err.name, errorMessage: err.message };
  return { errorName: 'UnknownError', errorMessage: String(err) };
}

function envBool(name: string): boolean {
  return String(process.env[name] ?? '').toLowerCase() === 'true';
}

function isDevEnv(): boolean {
  const appEnv = (
    process.env.APP_ENV ??
    process.env.NODE_ENV ??
    'development'
  ).toLowerCase();
  return appEnv === 'development';
}

function parseSampleRate(value: string | undefined, fallback: number): number {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(1, Math.max(0, n));
}

@Injectable()
export class PrismaService
  extends PrismaClient<
    Prisma.PrismaClientOptions,
    'query' | 'info' | 'warn' | 'error'
  >
  implements OnModuleInit, OnModuleDestroy
{
  constructor(private readonly logger: AppLogger) {
    const connectionString = process.env.DATABASE_URL;
    if (!connectionString) throw new Error('DATABASE_URL is not set');

    const adapter = new PrismaPg({ connectionString });

    const dev = isDevEnv();
    const enableQueries = dev && envBool('PRISMA_LOG_QUERIES');

    const log: Prisma.LogDefinition[] = [
      { emit: 'event', level: 'warn' },
      { emit: 'event', level: 'error' },
      ...(dev
        ? ([{ emit: 'event', level: 'info' }] as Prisma.LogDefinition[])
        : []),
      ...(enableQueries
        ? ([{ emit: 'event', level: 'query' }] as Prisma.LogDefinition[])
        : []),
    ];

    super({ adapter, log });

    this.logger.setContext(PrismaService.name);
    this.attachPrismaHooks();
  }

  async onModuleInit() {
    this.logger.log('Connecting to database', PrismaService.name, {
      event: 'prisma.connect.start',
    });

    try {
      await this.$connect();
      this.logger.log('Database connected', PrismaService.name, {
        event: 'prisma.connect.success',
      });
    } catch (err: unknown) {
      this.logger.error(
        'Database connection failed',
        undefined,
        PrismaService.name,
        {
          event: 'prisma.connect.fail',
          ...errMeta(err),
        },
      );
      throw err;
    }
  }

  async onModuleDestroy() {
    this.logger.log('Disconnecting from database', PrismaService.name, {
      event: 'prisma.disconnect.start',
    });

    try {
      await this.$disconnect();
      this.logger.log('Database disconnected', PrismaService.name, {
        event: 'prisma.disconnect.success',
      });
    } catch (err: unknown) {
      this.logger.error(
        'Database disconnect failed',
        undefined,
        PrismaService.name,
        {
          event: 'prisma.disconnect.fail',
          ...errMeta(err),
        },
      );
      throw err;
    }
  }

  private attachPrismaHooks() {
    this.$on('warn', (e: Prisma.LogEvent) => {
      this.logger.warn('Prisma warning', PrismaService.name, {
        event: 'prisma.warn',
        message: e.message,
        target: e.target,
      });
    });

    this.$on('error', (e: Prisma.LogEvent) => {
      this.logger.error('Prisma error', undefined, PrismaService.name, {
        event: 'prisma.error',
        message: e.message,
        target: e.target,
      });
    });

    if (isDevEnv()) {
      this.$on('info', (e: Prisma.LogEvent) => {
        this.logger.debug('Prisma info', PrismaService.name, {
          event: 'prisma.info',
          message: e.message,
          target: e.target,
        });
      });
    }

    const enableQueries = isDevEnv() && envBool('PRISMA_LOG_QUERIES');
    if (enableQueries) {
      const rate = parseSampleRate(process.env.PRISMA_QUERY_SAMPLE_RATE, 0.05);

      this.$on('query', (e: Prisma.QueryEvent) => {
        if (Math.random() > rate) return;

        const queryHash = crypto
          .createHash('sha256')
          .update(String(e.query ?? ''), 'utf8')
          .digest('hex')
          .slice(0, 16);

        this.logger.debug('Prisma query', PrismaService.name, {
          event: 'prisma.query',
          durationMs: e.duration,
          queryHash,
        });
      });

      this.logger.warn(
        'Prisma query logging enabled (dev only)',
        PrismaService.name,
        {
          event: 'prisma.query_logging.enabled',
          sampleRate: rate,
          note: 'Raw SQL is not logged; only query hash + duration',
        },
      );
    }
  }
}
