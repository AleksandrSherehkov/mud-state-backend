import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { SchedulerRegistry } from '@nestjs/schedule';
import { CronJob } from 'cron';
import { ConfigService } from '@nestjs/config';

import { AppLogger } from 'src/logger/logger.service';
import { AuthMaintenanceService } from 'src/auth/auth-maintenance.service';

const JOB_NAME = 'login-identifier-security-cleanup-job';

@Injectable()
export class LoginIdentifierSecurityCleanupJob
  implements OnModuleInit, OnModuleDestroy
{
  constructor(
    private readonly configService: ConfigService,
    private readonly schedulerRegistry: SchedulerRegistry,
    private readonly logger: AppLogger,
    private readonly authMaintenanceService: AuthMaintenanceService,
  ) {
    this.logger.setContext(LoginIdentifierSecurityCleanupJob.name);
  }

  onModuleInit(): void {
    const enabled = this.configService.get<boolean>(
      'LOGIN_IDENTIFIER_RETENTION_ENABLED',
      true,
    );

    if (!enabled) {
      this.logger.log(
        'Login identifier security cleanup job disabled',
        LoginIdentifierSecurityCleanupJob.name,
        {
          event: 'cleanup.login_identifier_security.job_disabled',
        },
      );
      return;
    }

    const cron = this.configService.get<string>(
      'LOGIN_IDENTIFIER_RETENTION_CRON',
      '15 0 * * *',
    );

    const job = new CronJob(cron, () => {
      void this.runCleanup();
    });

    this.schedulerRegistry.addCronJob(JOB_NAME, job);
    job.start();

    this.logger.log(
      'Login identifier security cleanup job started',
      LoginIdentifierSecurityCleanupJob.name,
      {
        event: 'cleanup.login_identifier_security.job_started',
        cron,
      },
    );
  }

  async onModuleDestroy(): Promise<void> {
    try {
      const job = this.schedulerRegistry.getCronJob(JOB_NAME);

      await Promise.resolve(job.stop());

      this.schedulerRegistry.deleteCronJob(JOB_NAME);
    } catch {
      // noop: job may not exist (e.g. tests / partial bootstrap)
    }
  }

  private async runCleanup(): Promise<void> {
    const olderThanDays = this.configService.get<number>(
      'LOGIN_IDENTIFIER_RETENTION_DAYS',
      90,
    );

    const deleteLimit = this.configService.get<number>(
      'LOGIN_IDENTIFIER_RETENTION_DELETE_LIMIT',
      5000,
    );

    try {
      await this.authMaintenanceService.cleanLoginIdentifierSecurity(
        olderThanDays,
        deleteLimit,
      );
    } catch (error: unknown) {
      this.logger.error(
        'Login identifier security cleanup job failed',
        error instanceof Error ? error.stack : undefined,
        LoginIdentifierSecurityCleanupJob.name,
        {
          event: 'cleanup.login_identifier_security.job_failed',
          olderThanDays,
          deleteLimit,
          errorMessage:
            error instanceof Error ? error.message : 'Unknown error',
        },
      );
    }
  }
}
