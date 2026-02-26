import { Module } from '@nestjs/common';

import { LoggerModule } from 'src/logger/logger.module';
import { AuthModule } from 'src/auth/auth.module';
import { TokenCleanupJob } from './token-cleanup.job';
import { ThrottleRedisMonitorJob } from './throttle-redis-monitor.job';

@Module({
  imports: [LoggerModule, AuthModule],
  providers: [TokenCleanupJob, ThrottleRedisMonitorJob],
})
export class JobsModule {}
