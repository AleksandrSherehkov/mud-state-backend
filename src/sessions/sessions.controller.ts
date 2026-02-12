import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Post,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiTags,
} from '@nestjs/swagger';
import { Role } from '@prisma/client';

import { CurrentUser } from 'src/common/decorators/current-user.decorator';
import { Roles } from 'src/common/decorators/roles.decorator';

import {
  ApiListErrorResponses,
  ApiMutationErrorResponses,
} from 'src/common/swagger/api-exceptions';
import { ApiRolesAccess } from 'src/common/swagger/api-roles';

import { Throttle } from '@nestjs/throttler';

import { TerminateSessionDto } from './dto/terminate-session.dto';
import { FullSessionDto } from './dto/full-session.dto';
import { TerminateCountResponseDto } from './dto/terminate-count-response.dto';
import { TerminateResultDto } from './dto/terminate-result.dto';

import { UserFromJwt } from 'src/common/types/user-from-jwt';
import { SESSIONS_SIDE_EFFECTS } from 'src/common/swagger/sessions.swagger';
import { ApiSessionsLinks } from 'src/common/swagger/sessions.links';
import { THROTTLE_SESSIONS } from 'src/common/throttle/throttle-env';

import { SessionsHttpService } from './sessions-http.service';
import { RequireFreshAccess } from 'src/common/decorators/require-fresh-access.decorator';

@ApiTags('sessions')
@Controller({ path: 'sessions', version: '1' })
@ApiBearerAuth('access_bearer')
export class SessionsController {
  constructor(private readonly http: SessionsHttpService) {}

  @Get('me')
  @Throttle({ default: THROTTLE_SESSIONS.me })
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
  @ApiListErrorResponses({
    includeBadRequest: false,
    includeForbidden: false,
    unauthorizedDescription: 'Недійсний access token або неактивна сесія',
    unauthorizedMessageExample: 'Session is not active',
  })
  mySessions(@CurrentUser('userId') userId: string): Promise<FullSessionDto[]> {
    return this.http.mySessions(userId);
  }

  @Post('terminate-others')
  @RequireFreshAccess(120)
  @Throttle({ default: THROTTLE_SESSIONS.terminateOthers })
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
    unauthorizedDescription:
      'Недійсний access token, неактивна сесія або токен застарів для fresh-access',
    unauthorizedMessageExample: 'Токен відкликано або недійсний',
  })
  terminateOthers(
    @CurrentUser() user: UserFromJwt,
  ): Promise<TerminateCountResponseDto> {
    return this.http.terminateOthers({ userId: user.userId, sid: user.sid });
  }

  @Post('terminate')
  @RequireFreshAccess(120)
  @Throttle({ default: THROTTLE_SESSIONS.terminate })
  @HttpCode(200)
  @ApiOperation({
    summary: 'Завершити конкретну сесію за sessionId',
    operationId: 'sessions_terminate',
  })
  @ApiRolesAccess('AUTHENTICATED', {
    sideEffects: SESSIONS_SIDE_EFFECTS.terminateSpecific,
    notes: [
      'Потрібна авторизація (Bearer access token).',
      'Завершує рівно 1 сесію за (userId + sessionId).',
      'Також відкликає refresh-токени, пов’язані з цією сесією.',
    ],
  })
  @ApiBody({ type: TerminateSessionDto })
  @ApiSessionsLinks.terminate200()
  @ApiMutationErrorResponses({
    includeConflict: false,
    includeForbidden: false,
    unauthorizedDescription:
      'Недійсний access token, неактивна сесія або токен застарів для fresh-access',
    unauthorizedMessageExample: 'Токен відкликано або недійсний',
  })
  terminateSpecific(
    @CurrentUser('userId') userId: string,
    @Body() dto: TerminateSessionDto,
  ): Promise<TerminateResultDto> {
    return this.http.terminateSpecific(userId, dto);
  }

  @Get(':userId')
  @Throttle({ default: THROTTLE_SESSIONS.getUser })
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
  @ApiListErrorResponses({
    unauthorizedDescription: 'Недійсний access token або неактивна сесія',
    unauthorizedMessageExample: 'Session is not active',
    forbiddenDescription:
      'Недостатньо прав доступу (потрібна роль ADMIN/MODERATOR)',
    forbiddenMessageExample: 'Недостатньо прав доступу',
  })
  getUserSessions(
    @Param('userId', new ParseUUIDPipe({ version: '4' })) userId: string,
  ): Promise<FullSessionDto[]> {
    return this.http.getUserSessions(userId);
  }
}
