import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';

import { PrismaModule } from 'src/prisma/prisma.module';
import { LoggerModule } from 'src/logger/logger.module';
import { ValidatorsModule } from 'src/common/validators/validators.module';
import { UsersHttpService } from './users-http.service';

@Module({
  imports: [PrismaModule, LoggerModule, ValidatorsModule],
  providers: [UsersService, UsersHttpService],
  controllers: [UsersController],
  exports: [UsersService],
})
export class UsersModule {}
