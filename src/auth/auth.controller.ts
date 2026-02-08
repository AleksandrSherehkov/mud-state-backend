import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response as ExpressResponse } from 'express';

import {
  ApiBearerAuth,
  ApiBody,
  ApiCookieAuth,
  ApiHeader,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';

import { Throttle } from '@nestjs/throttler';

import {
  ApiMutationErrorResponses,
  ApiQueryErrorResponses,
} from 'src/common/swagger/api-exceptions';
import { ApiRolesAccess } from 'src/common/swagger/api-roles';
import { AUTH_SIDE_EFFECTS } from 'src/common/swagger/auth.swagger';
import { ApiAuthLinks } from 'src/common/swagger/auth.links';

import { CsrfGuard } from 'src/common/guards/csrf.guard';

import { CurrentUser } from 'src/common/decorators/current-user.decorator';

import { THROTTLE_AUTH } from 'src/common/throttle/throttle-env';

import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

import { TokenResponseDto } from './dto/token-response.dto';
import { MeResponseDto } from './dto/me-response.dto';
import { LogoutResponseDto } from './dto/logout-response.dto';
import { RegisterResponseDto } from './dto/register-response.dto';

import { AuthHttpService } from './auth-http.service';
import { Public } from 'src/common/decorators/public.decorator';

@ApiTags('auth')
@Controller({
  path: 'auth',
  version: '1',
})
export class AuthController {
  constructor(private readonly http: AuthHttpService) {}

  @Post('register')
  @Public()
  @UseGuards(CsrfGuard)
  @ApiCookieAuth('csrf_cookie')
  @ApiSecurity('csrf_header')
  @ApiHeader({
    name: 'X-CSRF-Token',
    required: true,
    description: 'CSRF token (повинен збігатися зі значенням cookie csrfToken)',
  })
  @Throttle({ default: THROTTLE_AUTH.register })
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
    includeForbidden: true,
    includeConflict: true,
  })
  register(
    @Body() dto: RegisterDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: ExpressResponse,
  ): Promise<RegisterResponseDto> {
    return this.http.register(dto, req, res);
  }

  @Post('login')
  @Public()
  @UseGuards(CsrfGuard)
  @ApiCookieAuth('csrf_cookie')
  @ApiSecurity('csrf_header')
  @ApiHeader({
    name: 'X-CSRF-Token',
    required: true,
    description: 'CSRF token (повинен збігатися зі значенням cookie csrfToken)',
  })
  @HttpCode(200)
  @Throttle({ default: THROTTLE_AUTH.login })
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
    includeForbidden: true,
    includeConflict: false,
    unauthorizedDescription: 'Невірний email або пароль',
    unauthorizedMessageExample: 'Невірний email або пароль',
  })
  login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: ExpressResponse,
  ): Promise<TokenResponseDto> {
    return this.http.login(dto, req, res);
  }

  @Get('csrf')
  @Public()
  @HttpCode(204)
  @Throttle({ default: THROTTLE_AUTH.csrf })
  @ApiOperation({
    summary: 'Видати CSRF cookie (double-submit)',
    operationId: 'auth_csrf',
  })
  @ApiRolesAccess('PUBLIC', {
    sideEffects: ['Sets csrfToken cookie (non-HttpOnly, short-lived)'],
    notes: [
      'Потрібен для відновлення CSRF cookie, якщо вона протухла/очистилась.',
      'Не вимагає auth.',
    ],
  })
  csrf(
    @Req() req: Request,
    @Res({ passthrough: true }) res: ExpressResponse,
  ): void {
    return this.http.csrf(req, res);
  }

  @Post('refresh')
  @Public()
  @HttpCode(200)
  @UseGuards(CsrfGuard)
  @ApiCookieAuth('refresh_cookie')
  @ApiCookieAuth('csrf_cookie')
  @ApiSecurity('csrf_header')
  @ApiHeader({
    name: 'X-CSRF-Token',
    required: true,
    description: 'CSRF token (должен совпадать со значением cookie csrfToken)',
  })
  @Throttle({ default: THROTTLE_AUTH.refresh })
  @ApiOperation({ summary: 'Оновлення токенів', operationId: 'auth_refresh' })
  @ApiRolesAccess('PUBLIC', {
    sideEffects: AUTH_SIDE_EFFECTS.refresh,
    notes: [
      'Refresh має rate limit (Throttle).',
      'При reuse/revoked повертається 401.',
      'Refresh “claim” одноразовий: попередній jti відкликається та його сесія завершується.',
    ],
  })
  @ApiAuthLinks.refresh200()
  @ApiMutationErrorResponses({
    includeForbidden: true,
    includeConflict: false,
    unauthorizedDescription:
      'Refresh токен недійсний / відкликаний / reuse detected',
    unauthorizedMessageExample: 'Токен відкликано або недійсний',
  })
  refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: ExpressResponse,
  ): Promise<TokenResponseDto> {
    return this.http.refresh(req, res);
  }

  @Post('logout')
  @UseGuards(CsrfGuard)
  @ApiCookieAuth('csrf_cookie')
  @ApiSecurity('csrf_header')
  @ApiHeader({
    name: 'X-CSRF-Token',
    required: true,
    description: 'CSRF token (повинен збігатися зі значенням cookie csrfToken)',
  })
  @Throttle({ default: THROTTLE_AUTH.logout })
  @ApiBearerAuth('access_bearer')
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
    includeForbidden: true,
    notFoundMessage: 'Користувача не знайдено',
    unauthorizedDescription: 'Недійсний access token або сесія вже завершена',
    unauthorizedMessageExample: 'Session is not active',
  })
  logout(
    @CurrentUser('userId') userId: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: ExpressResponse,
  ): Promise<LogoutResponseDto> {
    return this.http.logout(userId, req, res);
  }

  @Get('me')
  @Throttle({ default: THROTTLE_AUTH.me })
  @ApiBearerAuth('access_bearer')
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
  getMe(@CurrentUser('userId') userId: string): Promise<MeResponseDto> {
    return this.http.getMe(userId);
  }
}
