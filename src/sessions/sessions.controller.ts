import { Body, Controller, Get, Param, Post, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { TerminateSessionDto } from 'src/auth/dto/terminate-session.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { RefreshTokenService } from './refresh-token.service';
import { SessionService } from './session.service';

import { UserFromJwt } from 'src/auth/types/user-from-jwt';

@ApiTags('sessions')
@Controller({
  path: 'sessions',
  version: '1',
})
@UseGuards(JwtAuthGuard, RolesGuard)
@ApiBearerAuth()
export class SessionsController {
  constructor(
    private readonly sessionService: SessionService,
    private readonly refreshTokenService: RefreshTokenService,
  ) {}

  @Get('me')
  async mySessions(@CurrentUser('userId') userId: string) {
    const sessions = await this.sessionService.getAllUserSessions(userId);

    return sessions.map((s) => ({
      id: s.id,
      ip: s.ip ?? '',
      userAgent: s.userAgent ?? '',
      isActive: s.isActive,
      startedAt: s.startedAt.toISOString(),
      endedAt: s.endedAt?.toISOString() ?? null,
    }));
  }

  @Post('terminate-others')
  async terminateOthers(@CurrentUser() user: UserFromJwt) {
    const res = await this.sessionService.terminateOtherSessions(
      user.userId,
      user.sid,
    );

    return { terminatedCount: res.count };
  }

  @Post('terminate')
  async terminateSpecific(
    @CurrentUser('userId') userId: string,
    @Body() dto: TerminateSessionDto,
  ) {
    const res = await this.sessionService.terminateSpecificSession(
      userId,
      dto.ip,
      dto.userAgent,
    );

    return { terminated: res.count > 0 };
  }

  // ---- admin only ----

  @Get(':userId')
  @Roles(Role.ADMIN, Role.MODERATOR)
  async getUserSessions(@Param('userId') userId: string) {
    const tokens = await this.refreshTokenService.getActiveTokens(userId);

    return tokens.map((t) => ({
      jti: t.jti,
      ip: t.ip ?? '',
      userAgent: t.userAgent ?? '',
      createdAt: t.createdAt.toISOString(),
    }));
  }
}
