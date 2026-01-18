import { Module } from '@nestjs/common';

import { LoggerModule } from 'src/logger/logger.module';
import { UsersModule } from 'src/users/users.module';
import { TokenCleanupJob } from './token-cleanup.job';

@Module({
  imports: [LoggerModule, UsersModule],
  providers: [TokenCleanupJob],
})
export class JobsModule {}
