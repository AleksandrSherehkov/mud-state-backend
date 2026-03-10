import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';

import { PrismaModule } from 'src/prisma/prisma.module';
import { LoggerModule } from 'src/logger/logger.module';
import { ValidatorsModule } from 'src/common/security/validators/validators.module';
import { UsersHttpService } from './users-http.service';
import { SessionsModule } from 'src/sessions/sessions.module';

@Module({
  imports: [PrismaModule, LoggerModule, ValidatorsModule, SessionsModule],
  providers: [UsersService, UsersHttpService],
  controllers: [UsersController],
  exports: [UsersService],
})
export class UsersModule {}
