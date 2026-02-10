import { Module } from '@nestjs/common';
import { LoggerModule } from 'src/logger/logger.module';
import { PrismaModule } from 'src/prisma/prisma.module';
import { SessionsController } from './sessions.controller';

import { SessionsService } from './sessions.service';
import { RefreshTokenService } from './refresh-token.service';
import { SessionsHttpService } from './sessions-http.service';

@Module({
  imports: [PrismaModule, LoggerModule],
  providers: [SessionsService, RefreshTokenService, SessionsHttpService],
  controllers: [SessionsController],
  exports: [SessionsService, RefreshTokenService],
})
export class SessionsModule {}
