import { Module } from '@nestjs/common';

import { PrismaModule } from 'src/prisma/prisma.module';
import { LoggerModule } from 'src/logger/logger.module';
import { UsersModule } from 'src/users/users.module';

import { RiskEngineService } from './risk-engine.service';

@Module({
  imports: [PrismaModule, LoggerModule, UsersModule],
  providers: [RiskEngineService],
  exports: [RiskEngineService],
})
export class RiskEngineModule {}
