import { Body, Controller, Get, Param, Post, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { Role, Session as PrismaSession } from '@prisma/client';
import { CurrentUser } from 'src/common/decorators/current-user.decorator';
import { Roles } from 'src/common/decorators/roles.decorator';
import { TerminateSessionDto } from 'src/sessions/dto/terminate-session.dto';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { RefreshTokenService } from './refresh-token.service';
import { SessionService } from './session.service';
import { UserFromJwt } from 'src/common/types/user-from-jwt';

@ApiTags('sessions')
@Controller({ path: 'sessions', version: '1' })
@UseGuards(JwtAuthGuard, RolesGuard)
@ApiBearerAuth()
export class SessionsController {
  constructor(
    private readonly sessionService: SessionService,
    private readonly refreshTokenService: RefreshTokenService,
  ) {}

  private toDto(s: PrismaSession) {
    return {
      id: s.id,
      ip: s.ip ?? '',
      userAgent: s.userAgent ?? '',
      isActive: s.isActive,
      startedAt: s.startedAt.toISOString(),
      endedAt: s.endedAt?.toISOString() ?? null,
    };
  }

  private async listUserSessions(userId: string) {
    const sessions = await this.sessionService.getAllUserSessions(userId);
    return sessions.map((s) => this.toDto(s));
  }

  @Get('me')
  async mySessions(@CurrentUser('userId') userId: string) {
    return this.listUserSessions(userId);
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

  @Get(':userId')
  @Roles(Role.ADMIN, Role.MODERATOR)
  async getUserSessions(@Param('userId') userId: string) {
    return this.listUserSessions(userId);
  }
}
