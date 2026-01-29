import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { SchedulerRegistry } from '@nestjs/schedule';
import { CronJob } from 'cron';
import { ConfigService } from '@nestjs/config';

import { AppLogger } from 'src/logger/logger.service';
import { AuthMaintenanceService } from 'src/auth/auth-maintenance.service';

const DEFAULT_CLEANUP_CRON = '0 0 * * *';
const DEFAULT_CLEANUP_DAYS = 7;
const JOB_NAME = 'token-cleanup-job';

function errMeta(err: unknown) {
  if (err instanceof Error) {
    return { errorName: err.name, errorMessage: err.message };
  }
  return { errorName: 'UnknownError', errorMessage: String(err) };
}

@Injectable()
export class TokenCleanupJob implements OnModuleInit, OnModuleDestroy {
  constructor(
    private readonly config: ConfigService,
    private readonly schedulerRegistry: SchedulerRegistry,
    private readonly logger: AppLogger,
    private readonly maintenance: AuthMaintenanceService,
  ) {
    this.logger.setContext(TokenCleanupJob.name);
  }

  onModuleInit() {
    const cron =
      this.config.get<string>('TOKEN_CLEANUP_CRON') ?? DEFAULT_CLEANUP_CRON;

    const days = this.getDays();

    const job = new CronJob(cron, () => {
      void this.handleCleanup();
    });

    this.schedulerRegistry.addCronJob(JOB_NAME, job);
    job.start();

    this.logger.debug('Token cleanup job registered', TokenCleanupJob.name, {
      event: 'cleanup.init',
      cron,
      days,
    });
  }

  onModuleDestroy() {
    try {
      const job = this.schedulerRegistry.getCronJob(JOB_NAME);
      job.stop();
      this.schedulerRegistry.deleteCronJob(JOB_NAME);

      this.logger.debug('Token cleanup job stopped', TokenCleanupJob.name, {
        event: 'cleanup.stop',
      });
    } catch {
      // noop: job may not exist (e.g. tests / partial bootstrap)
    }
  }

  private getDays(): number {
    return this.config.get<number>('TOKEN_CLEANUP_DAYS', DEFAULT_CLEANUP_DAYS);
  }

  async handleCleanup() {
    const days = this.getDays();

    this.logger.debug('Token cleanup start', TokenCleanupJob.name, {
      event: 'cleanup.start',
      days,
    });

    try {
      const [deletedTokens, deletedSessions] = await Promise.all([
        this.maintenance.cleanRevokedTokens(days),
        this.maintenance.cleanInactiveSessions(days),
      ]);

      this.logger.debug('Token cleanup finished', TokenCleanupJob.name, {
        event: 'cleanup.done',
        days,
        deletedTokens,
        deletedSessions,
      });

      if (deletedTokens > 0 || deletedSessions > 0) {
        this.logger.log('Token cleanup deleted records', TokenCleanupJob.name, {
          event: 'cleanup.deleted',
          days,
          deletedTokens,
          deletedSessions,
        });
      } else {
        this.logger.debug('Token cleanup noop', TokenCleanupJob.name, {
          event: 'cleanup.noop',
          days,
        });
      }
    } catch (err: unknown) {
      const trace = err instanceof Error ? err.stack : undefined;

      this.logger.error('Token cleanup failed', trace, TokenCleanupJob.name, {
        event: 'cleanup.fail',
        days,
        ...errMeta(err),
      });
    }
  }
}
