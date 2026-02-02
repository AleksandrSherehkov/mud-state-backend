import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshDto } from './dto/refresh.dto';

import { AuthService } from './auth.service';

import { ApiBearerAuth, ApiBody, ApiOperation, ApiTags } from '@nestjs/swagger';
import {
  ApiMutationErrorResponses,
  ApiQueryErrorResponses,
} from 'src/common/swagger/api-exceptions';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { SkipThrottle, Throttle } from '@nestjs/throttler';

import { TokenResponseDto } from './dto/token-response.dto';
import { MeResponseDto } from './dto/me-response.dto';
import { extractRequestInfo } from 'src/common/helpers/request-info';
import { LogoutResponseDto } from './dto/logout-response.dto';
import { RegisterResponseDto } from './dto/register-response.dto';
import { ApiRolesAccess } from 'src/common/swagger/api-roles';
import { AUTH_SIDE_EFFECTS } from 'src/common/swagger/auth.swagger';
import { ApiAuthLinks } from 'src/common/swagger/auth.links';

@ApiTags('auth')
@Controller({
  path: 'auth',
  version: '1',
})
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @Throttle({ default: { limit: 3, ttl: 60 } })
  @ApiOperation({
    summary: 'Реєстрація нового користувача',
    operationId: 'auth_register',
  })
  @ApiRolesAccess('PUBLIC', {
    sideEffects: AUTH_SIDE_EFFECTS.register,
    notes: ['Створює першу сесію та refresh-токен для нового користувача.'],
  })
  @ApiBody({ type: RegisterDto })
  @ApiAuthLinks.register201()
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
  @Throttle({ default: { limit: 5, ttl: 60 } })
  @ApiOperation({ summary: 'Вхід користувача', operationId: 'auth_login' })
  @ApiRolesAccess('PUBLIC', {
    sideEffects: AUTH_SIDE_EFFECTS.login,
    notes: [
      'Перед видачею нових токенів завершує активні сесії та відкликає попередні refresh-токени користувача.',
    ],
  })
  @ApiBody({ type: LoginDto })
  @ApiAuthLinks.login200()
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
    const result = await this.authService.login(dto, ip, userAgent);
    return new TokenResponseDto(result);
  }

  @Post('refresh')
  @HttpCode(200)
  @Throttle({ default: { limit: 10, ttl: 60 } })
  @ApiOperation({ summary: 'Оновлення токенів', operationId: 'auth_refresh' })
  @ApiRolesAccess('PUBLIC', {
    sideEffects: AUTH_SIDE_EFFECTS.refresh,
    notes: [
      'Refresh має rate limit (Throttle).',
      'При reuse/revoked повертається 401.',
      'Refresh “claim” одноразовий: попередній jti відкликається та його сесія завершується.',
    ],
  })
  @ApiBody({ type: RefreshDto })
  @ApiAuthLinks.refresh200()
  @ApiMutationErrorResponses({
    includeForbidden: false,
    includeConflict: false,
    unauthorizedDescription:
      'Refresh токен недійсний / відкликаний / reuse detected',
    unauthorizedMessageExample: 'Токен відкликано або недійсний',
  })
  async refresh(
    @Body() dto: RefreshDto,
    @Req() req: Request,
  ): Promise<TokenResponseDto> {
    const { ip, userAgent } = extractRequestInfo(req);
    const result = await this.authService.refresh(
      dto.refreshToken,
      ip,
      userAgent,
    );
    return new TokenResponseDto(result);
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
  @ApiRolesAccess('AUTHENTICATED', {
    sideEffects: AUTH_SIDE_EFFECTS.logout,
    notes: [
      'Logout є ідемпотентним: повторний виклик повертає 200, якщо запит пройшов JwtAuthGuard.',
      'Всі сесії користувача завершуються, а всі refresh-токени відкликаються.',
    ],
  })
  @ApiAuthLinks.logout200()
  @ApiMutationErrorResponses({
    includeConflict: false,
    includeTooManyRequests: false,
    includeBadRequest: false,
    notFoundMessage: 'Користувача не знайдено',
    unauthorizedDescription: 'Недійсний access token або сесія вже завершена',
    unauthorizedMessageExample: 'Session is not active',
  })
  async logout(
    @CurrentUser('userId') userId: string,
  ): Promise<LogoutResponseDto> {
    const result = await this.authService.logout(userId);
    return new LogoutResponseDto({
      loggedOut: Boolean(result),
      terminatedAt: result?.terminatedAt ?? null,
    });
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @SkipThrottle()
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Отримати інформацію про себе',
    operationId: 'auth_me',
  })
  @ApiRolesAccess('AUTHENTICATED', {
    sideEffects: AUTH_SIDE_EFFECTS.getMe,
    notes: ['Повертає профіль користувача з БД за userId із access token.'],
  })
  @ApiAuthLinks.me200()
  @ApiQueryErrorResponses({
    notFoundMessage: 'Користувача не знайдено',
    includeBadRequest: false,
    includeTooManyRequests: false,
  })
  async getMe(@CurrentUser('userId') userId: string): Promise<MeResponseDto> {
    const user = await this.authService.getMe(userId);
    return new MeResponseDto(user);
  }
}
