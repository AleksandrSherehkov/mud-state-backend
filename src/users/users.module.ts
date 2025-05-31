import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { TokenCleanupService } from './token-cleanup.service';

@Module({
  providers: [UsersService, TokenCleanupService],
  controllers: [UsersController],
  exports: [UsersService],
})
export class UsersModule {}
