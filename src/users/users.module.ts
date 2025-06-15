import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { TokenCleanupService } from './token-cleanup.service';
import { PrismaModule } from 'src/prisma/prisma.module';
import { LoggerModule } from 'src/logger/logger.module';

@Module({
  imports: [PrismaModule, LoggerModule],
  providers: [UsersService, TokenCleanupService],
  controllers: [UsersController],
  exports: [UsersService],
})
export class UsersModule {}
