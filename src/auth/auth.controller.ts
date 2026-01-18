import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  Get,
  HttpCode,
  UnauthorizedException,
  NotFoundException,
  Param,
  Post,
  Req,
  UseGuards,
  Query,
} from '@nestjs/common';
import { Request } from 'express';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshDto } from './dto/refresh.dto';

import { AuthService } from './auth.service';

import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiTags,
} from '@nestjs/swagger';
import {
  ApiListErrorResponses,
  ApiMutationErrorResponses,
  ApiQueryErrorResponses,
} from 'src/common/swagger/api-exceptions';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { CurrentUser } from './decorators/current-user.decorator';
import { SkipThrottle, Throttle } from '@nestjs/throttler';

import { TokenResponseDto } from './dto/token-response.dto';
import { MeResponseDto } from './dto/me-response.dto';
import { extractRequestInfo } from 'src/common/helpers/request-info';
import { TerminateSessionDto } from './dto/terminate-session.dto';
import { ActiveSessionDto } from './dto/active-session.dto';
import { RefreshTokenSessionDto } from './dto/refresh-token-session.dto';
import { TerminateCountResponseDto } from './dto/terminate-count-response.dto';
import { TerminateResultDto } from './dto/terminate-result.dto';
import { FullSessionDto } from './dto/full-session.dto';
import { Roles } from './decorators/roles.decorator';
import { RolesGuard } from './guards/roles.guard';
import { LogoutResponseDto } from './dto/logout-response.dto';
import { RegisterResponseDto } from './dto/register-response.dto';
import { UserFromJwt } from './types/user-from-jwt';
import { Role } from '@prisma/client';
import { SessionService } from './session.service';
import { RefreshTokenService } from './refresh-token.service';
import { UsersService } from 'src/users/users.service';

@ApiTags('auth')
@Controller({
  path: 'auth',
  version: '1',
})
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly sessionService: SessionService,
    private readonly refreshTokenService: RefreshTokenService,
    private readonly usersService: UsersService,
  ) {}

  @Post('register')
  @HttpCode(201)
  @ApiOperation({
    summary: 'Реєстрація нового користувача',
    description:
      'Створює нового користувача, одразу видає access/refresh токени та створює сесію.',
    operationId: 'auth_register',
  })
  @ApiBody({ type: RegisterDto })
  @ApiCreatedResponse({
    description: 'Користувач створений',
    type: RegisterResponseDto,
  })
  @ApiMutationErrorResponses({
    includeUnauthorized: false,
    includeForbidden: false,
    includeConflict: true,
    conflictDescription: 'Email вже використовується',
    conflictMessageExample: 'Електронна адреса вже використовується',
  })
  async register(
    @Body() dto: RegisterDto,
    @Req() req: Request,
  ): Promise<RegisterResponseDto> {
    const { ip, userAgent } = extractRequestInfo(req);

    const result = await this.authService.register(dto, ip, userAgent);
    return new RegisterResponseDto(result);
  }

  @Post('login')
  @HttpCode(200)
  @ApiOperation({ summary: 'Вхід користувача', operationId: 'auth_login' })
  @ApiBody({ type: LoginDto })
  @ApiOkResponse({
    description: 'Успішний логін',
    type: TokenResponseDto,
  })
  @ApiMutationErrorResponses({
    includeForbidden: false,
    includeConflict: false,
    unauthorizedDescription: 'Невірний email або пароль',
    unauthorizedMessageExample: 'Невірний email або пароль',
  })
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
  ): Promise<TokenResponseDto> {
    const { ip, userAgent } = extractRequestInfo(req);
    const result = await this.authService.login(dto, ip ?? '', userAgent ?? '');
    return {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      jti: result.jti,
    };
  }

  @Post('refresh')
  @HttpCode(200)
  @ApiOperation({ summary: 'Оновлення токенів', operationId: 'auth_refresh' })
  @ApiBody({ type: RefreshDto })
  @ApiOkResponse({ description: 'Нові токени', type: TokenResponseDto })
  @ApiMutationErrorResponses({
    includeForbidden: false,
    includeConflict: false,
    unauthorizedDescription:
      'Refresh токен недійсний / відкликаний / reuse detected',
    unauthorizedMessageExample: 'Токен відкликано або недійсний',
  })
  @SkipThrottle()
  @Throttle({ default: { limit: 10, ttl: 60 } })
  async refresh(
    @Body() dto: RefreshDto,
    @Req() req: Request,
  ): Promise<TokenResponseDto> {
    const { ip, userAgent } = extractRequestInfo(req);
    const result = await this.authService.refresh(
      dto.userId,
      dto.refreshToken,
      ip,
      userAgent,
    );
    return {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      jti: result.jti,
    };
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @SkipThrottle()
  @ApiBearerAuth()
  @HttpCode(200)
  @ApiOperation({
    summary: 'Вихід користувача (ревок refresh токенів + завершення сесій)',
    operationId: 'auth_logout',
  })
  @ApiOkResponse({ description: 'Користувач вийшов', type: LogoutResponseDto })
  @ApiMutationErrorResponses({
    includeConflict: false,
    notFoundMessage: 'Користувача не знайдено',
    badRequestDescription: 'Користувач вже вийшов із системи',
    badRequestMessageExample: 'Користувач вже вийшов із системи',
  })
  async logout(
    @CurrentUser('userId') userId: string,
  ): Promise<LogoutResponseDto> {
    const result = await this.authService.logout(userId);

    if (!result) {
      throw new BadRequestException('Користувач вже вийшов із системи');
    }

    return new LogoutResponseDto(result);
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @SkipThrottle()
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Отримати інформацію про себе',
    operationId: 'auth_me',
  })
  @ApiOkResponse({ description: 'Профіль користувача', type: MeResponseDto })
  @ApiQueryErrorResponses({
    notFoundMessage: 'Користувача не знайдено',
    includeBadRequest: false,
  })
  async getMe(@CurrentUser('userId') userId: string): Promise<MeResponseDto> {
    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new NotFoundException('Користувача не знайдено');
    }
    return new MeResponseDto(user);
  }

  @Get(':userId/sessions')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN, Role.MODERATOR)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Активні refresh токени (сесії) користувача за userId',
    operationId: 'auth_user_sessions',
  })
  @ApiOkResponse({
    description: 'Активні токени',
    type: [RefreshTokenSessionDto],
  })
  @ApiListErrorResponses({ includeBadRequest: false })
  @ApiParam({
    name: 'userId',
    description: 'UUID користувача',
    schema: { type: 'string', format: 'uuid' },
  })
  async getSessions(
    @Param('userId') userId: string,
  ): Promise<RefreshTokenSessionDto[]> {
    const tokens = await this.refreshTokenService.getActiveTokens(userId);
    return tokens.map((token) => ({
      jti: token.jti,
      ip: token.ip ?? '',
      userAgent: token.userAgent ?? '',
      createdAt: token.createdAt.toISOString(),
    }));
  }

  @Get('sessions/active')
  @ApiQuery({
    name: 'limit',
    required: false,
    description: '1..100 (default 50)',
    example: 50,
  })
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN, Role.MODERATOR)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Активні сесії поточного користувача',
    operationId: 'auth_sessions_active',
  })
  @ApiOkResponse({
    description: 'Список активних сесій з IP, User-Agent і часом старту',
    type: [ActiveSessionDto],
  })
  @ApiListErrorResponses({
    includeBadRequest: false,
  })
  async getActiveSessions(
    @CurrentUser('userId') userId: string,
    @Query('limit') limit?: string,
  ): Promise<ActiveSessionDto[]> {
    const raw = limit?.trim();
    const parsed = raw ? Number(raw) : Number.NaN;

    const take =
      Number.isFinite(parsed) && parsed > 0
        ? Math.min(Math.trunc(parsed), 100)
        : 50;
    const sessions = await this.sessionService.getActiveUserSessions(
      userId,
      take,
    );
    return sessions.map((session) => ({
      id: session.id,
      ip: session.ip ?? '',
      userAgent: session.userAgent ?? '',
      startedAt: session.startedAt.toISOString(),
    }));
  }

  @Post('sessions/terminate-others')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN, Role.MODERATOR)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Завершити всі інші сесії, крім поточної',
    operationId: 'auth_sessions_terminate_others',
  })
  @ApiOkResponse({
    description: 'Інші сесії завершено',
    type: TerminateCountResponseDto,
  })
  @ApiMutationErrorResponses({
    includeBadRequest: false,
    includeConflict: true,
    conflictDescription: 'Немає інших активних сесій',
    conflictMessageExample: 'Немає інших активних сесій для завершення',
  })
  async terminateOtherSessions(@CurrentUser() user: UserFromJwt | undefined) {
    if (!user) {
      throw new UnauthorizedException();
    }

    const result = await this.sessionService.terminateOtherSessions(
      user.userId,
      user.sid,
    );
    if (result.count === 0) {
      throw new ConflictException('Немає інших активних сесій');
    }
    return { terminatedCount: result.count };
  }

  @Get('sessions/me')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN, Role.MODERATOR)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Усі сесії поточного користувача',
    operationId: 'auth_sessions_me',
  })
  @ApiOkResponse({
    description: 'Усі сесії поточного користувача',
    type: [FullSessionDto],
  })
  @ApiListErrorResponses({ includeBadRequest: false })
  async getMySessions(
    @CurrentUser('userId') userId: string,
  ): Promise<FullSessionDto[]> {
    const sessions = await this.sessionService.getAllUserSessions(userId);
    return sessions.map((session) => ({
      id: session.id,
      ip: session.ip ?? '',
      userAgent: session.userAgent ?? '',
      isActive: session.isActive,
      startedAt: session.startedAt.toISOString(),
      endedAt: session.endedAt ? session.endedAt.toISOString() : null,
    }));
  }

  @Post('sessions/terminate')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN, Role.MODERATOR)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Завершити конкретну сесію за IP та User-Agent',
    operationId: 'auth_sessions_terminate',
  })
  @ApiOkResponse({
    description: 'Сесію завершено',
    type: TerminateResultDto,
  })
  @ApiMutationErrorResponses({
    includeConflict: false,
    includeBadRequest: true,
  })
  async terminateSpecificSession(
    @CurrentUser('userId') userId: string,
    @Body() dto: TerminateSessionDto,
  ) {
    const { ip, userAgent } = dto;

    const result = await this.sessionService.terminateSpecificSession(
      userId,
      ip,
      userAgent,
    );
    return { terminated: result.count > 0 };
  }
}
