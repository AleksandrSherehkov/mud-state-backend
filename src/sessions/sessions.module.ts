import { Module } from '@nestjs/common';
import { LoggerModule } from 'src/logger/logger.module';
import { PrismaModule } from 'src/prisma/prisma.module';
import { SessionsController } from './sessions.controller';

import { SessionService } from './session.service';
import { RefreshTokenService } from './refresh-token.service';
import { SessionsHttpService } from './sessions-http.service';

@Module({
  imports: [PrismaModule, LoggerModule],
  providers: [SessionService, RefreshTokenService, SessionsHttpService],
  controllers: [SessionsController],
  exports: [SessionService, RefreshTokenService],
})
export class SessionsModule {}
