import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiTags,
} from '@nestjs/swagger';
import { Role, Session as PrismaSession } from '@prisma/client';

import { CurrentUser } from 'src/common/decorators/current-user.decorator';
import { Roles } from 'src/common/decorators/roles.decorator';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';

import {
  ApiMutationErrorResponses,
  ApiQueryErrorResponses,
} from 'src/common/swagger/api-exceptions';
import { ApiRolesAccess } from 'src/common/swagger/api-roles';

import { SkipThrottle } from '@nestjs/throttler';

import { SessionService } from './session.service';
import { TerminateSessionDto } from './dto/terminate-session.dto';
import { FullSessionDto } from './dto/full-session.dto';
import { TerminateCountResponseDto } from './dto/terminate-count-response.dto';
import { TerminateResultDto } from './dto/terminate-result.dto';

import { UserFromJwt } from 'src/common/types/user-from-jwt';
import { SESSIONS_SIDE_EFFECTS } from 'src/common/swagger/sessions.swagger';
import { ApiSessionsLinks } from 'src/common/swagger/sessions.links';

@ApiTags('sessions')
@Controller({ path: 'sessions', version: '1' })
@UseGuards(JwtAuthGuard, RolesGuard)
@ApiBearerAuth()
export class SessionsController {
  constructor(private readonly sessionService: SessionService) {}

  private toFullSessionDto(s: PrismaSession): FullSessionDto {
    return {
      id: s.id,
      ip: s.ip ?? '',
      userAgent: s.userAgent ?? '',
      isActive: s.isActive,
      startedAt: s.startedAt.toISOString(),
      endedAt: s.endedAt?.toISOString() ?? null,
    };
  }

  private async listUserSessions(userId: string): Promise<FullSessionDto[]> {
    const sessions = await this.sessionService.getAllUserSessions(userId);
    return sessions.map((s) => this.toFullSessionDto(s));
  }

  @Get('me')
  @SkipThrottle()
  @ApiOperation({
    summary: 'Отримати список своїх сесій',
    operationId: 'sessions_mySessions',
  })
  @ApiRolesAccess('AUTHENTICATED', {
    sideEffects: SESSIONS_SIDE_EFFECTS.mySessions,
    notes: [
      'Потрібна авторизація (Bearer access token).',
      'Повертає всі сесії користувача (active + inactive).',
    ],
  })
  @ApiSessionsLinks.mySessions200()
  @ApiQueryErrorResponses({
    includeBadRequest: false,
    includeTooManyRequests: false,
    notFoundMessage: 'Ресурс не знайдено',
  })
  async mySessions(
    @CurrentUser('userId') userId: string,
  ): Promise<FullSessionDto[]> {
    return this.listUserSessions(userId);
  }

  @Post('terminate-others')
  @SkipThrottle()
  @HttpCode(200)
  @ApiOperation({
    summary: 'Завершити всі інші активні сесії (крім поточної)',
    operationId: 'sessions_terminateOthers',
  })
  @ApiRolesAccess('AUTHENTICATED', {
    sideEffects: SESSIONS_SIDE_EFFECTS.terminateOthers,
    notes: [
      'Потрібна авторизація (Bearer access token).',
      'Поточна сесія (sid з JWT) не завершується.',
      'Разом із завершенням сесій відкликаються refresh-токени, пов’язані з ними.',
    ],
  })
  @ApiSessionsLinks.terminateOthers200()
  @ApiMutationErrorResponses({
    includeConflict: false,
    includeForbidden: false,
    includeBadRequest: false,
    includeTooManyRequests: false,
    unauthorizedDescription: 'Недійсний access token або сесія вже завершена',
    unauthorizedMessageExample: 'Session is not active',
  })
  async terminateOthers(
    @CurrentUser() user: UserFromJwt,
  ): Promise<TerminateCountResponseDto> {
    const res = await this.sessionService.terminateOtherSessions(
      user.userId,
      user.sid,
    );

    return { terminatedCount: res.count };
  }

  @Post('terminate')
  @SkipThrottle()
  @HttpCode(200)
  @ApiOperation({
    summary: 'Завершити конкретну сесію за IP та User-Agent',
    operationId: 'sessions_terminate',
  })
  @ApiRolesAccess('AUTHENTICATED', {
    sideEffects: SESSIONS_SIDE_EFFECTS.terminateSpecific,
    notes: [
      'Потрібна авторизація (Bearer access token).',
      'Завершує сесію, яка збігається за (userId + ip + userAgent).',
      'Також відкликає refresh-токени, пов’язані з цією сесією.',
    ],
  })
  @ApiBody({ type: TerminateSessionDto })
  @ApiSessionsLinks.terminate200()
  @ApiMutationErrorResponses({
    includeConflict: false,
    includeForbidden: false,
    includeTooManyRequests: false,
    unauthorizedDescription: 'Недійсний access token або сесія вже завершена',
    unauthorizedMessageExample: 'Session is not active',
  })
  async terminateSpecific(
    @CurrentUser('userId') userId: string,
    @Body() dto: TerminateSessionDto,
  ): Promise<TerminateResultDto> {
    const res = await this.sessionService.terminateSpecificSession(
      userId,
      dto.ip,
      dto.userAgent,
    );

    return { terminated: res.count > 0 };
  }

  @Get(':userId')
  @SkipThrottle()
  @Roles(Role.ADMIN, Role.MODERATOR)
  @ApiOperation({
    summary: 'Отримати сесії користувача (ADMIN/MODERATOR)',
    operationId: 'sessions_getUserSessions',
  })
  @ApiRolesAccess([Role.ADMIN, Role.MODERATOR], {
    sideEffects: SESSIONS_SIDE_EFFECTS.getUserSessions,
    notes: [
      'Потрібна авторизація (Bearer access token).',
      'Доступно лише ADMIN/MODERATOR.',
    ],
  })
  @ApiParam({
    name: 'userId',
    description: 'UUID користувача',
    schema: { type: 'string', format: 'uuid' },
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @ApiSessionsLinks.userSessions200()
  @ApiQueryErrorResponses({
    notFoundMessage: 'Ресурс не знайдено',
    includeBadRequest: false,
    includeTooManyRequests: false,
  })
  async getUserSessions(
    @Param('userId') userId: string,
  ): Promise<FullSessionDto[]> {
    // Якщо хочеш суворий 404, коли користувача немає — можна додатково перевіряти через UsersService.
    // Зараз поведінка як була: поверне [] якщо сесій немає.
    return this.listUserSessions(userId);
  }
}
