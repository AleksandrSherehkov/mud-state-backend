import { Module } from '@nestjs/common';

import { LoggerModule } from 'src/logger/logger.module';
import { AuthModule } from 'src/auth/auth.module';
import { TokenCleanupJob } from './token-cleanup.job';
import { ThrottleRedisMonitorJob } from './throttle-redis-monitor.job';
import { LoginIdentifierSecurityCleanupJob } from './login-identifier-security-cleanup.job';

@Module({
  imports: [LoggerModule, AuthModule],
  providers: [
    TokenCleanupJob,
    ThrottleRedisMonitorJob,
    LoginIdentifierSecurityCleanupJob,
  ],
})
export class JobsModule {}
