import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { Request, Response as ExpressResponse } from 'express';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

import { AuthService } from './auth.service';

import {
  ApiBearerAuth,
  ApiBody,
  ApiCookieAuth,
  ApiHeader,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
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
import { randomUUID } from 'node:crypto';
import { CsrfGuard } from 'src/common/guards/csrf.guard';
import { getCookieString } from 'src/common/http/cookies';
import type { CookieOptions } from 'express-serve-static-core';
import { ConfigService } from '@nestjs/config';

@ApiTags('auth')
@Controller({
  path: 'auth',
  version: '1',
})
export class AuthController {
  private readonly apiPrefix: string;
  private readonly appEnv: string;
  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService,
  ) {
    this.apiPrefix = this.config.get<string>('API_PREFIX', 'api');
    this.appEnv = this.config.get<string>('APP_ENV', 'development');
  }
  private apiPath(): string {
    return `/${this.apiPrefix}`;
  }
  private isProd(): boolean {
    return (process.env.APP_ENV ?? 'development') === 'production';
  }
  private isRequestSecure(req: Request): boolean {
    // req.secure работает корректно при trust proxy
    if (req.secure) return true;

    const xfProto = req.header('x-forwarded-proto');
    return xfProto?.toLowerCase() === 'https';
  }

  private refreshCookieOptions(req: Request): CookieOptions {
    const secure = this.isProd() ? true : this.isRequestSecure(req);

    return {
      httpOnly: true,
      secure,
      sameSite: this.isProd() ? 'none' : 'lax',
      path: this.apiPath(),
      signed: true,
    };
  }
  private csrfCookieOptions(req: Request): CookieOptions {
    const secure = this.isProd() ? true : this.isRequestSecure(req);

    return {
      httpOnly: false, // double-submit: JS читает и кладёт в header
      secure,
      sameSite: this.isProd() ? 'none' : 'lax',
      path: this.apiPath(),
      maxAge: 15 * 60 * 1000, // 15 минут
    };
  }
  private setCsrfCookie(res: ExpressResponse, req: Request): string {
    const csrfToken = randomUUID();
    res.cookie('csrfToken', csrfToken, this.csrfCookieOptions(req));
    return csrfToken;
  }

  private setAuthCookies(
    res: ExpressResponse,
    req: Request,
    refreshToken: string,
  ): void {
    res.cookie('refreshToken', refreshToken, this.refreshCookieOptions(req));
    this.setCsrfCookie(res, req);
  }

  private clearAuthCookies(res: ExpressResponse, req: Request): void {
    res.clearCookie('refreshToken', this.refreshCookieOptions(req));
    res.clearCookie('csrfToken', this.csrfCookieOptions(req));
  }

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
  @ApiCookieAuth('refresh_cookie')
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
    @Res({ passthrough: true }) res: ExpressResponse,
  ): Promise<RegisterResponseDto> {
    const { ip, userAgent } = extractRequestInfo(req);

    const result = await this.authService.register(dto, ip, userAgent);

    this.setAuthCookies(res, req, result.refreshToken);

    return new RegisterResponseDto({
      id: result.id,
      email: result.email,
      role: result.role,
      createdAt: result.createdAt,
      accessToken: result.accessToken,
      jti: result.jti,
    });
  }

  @Post('login')
  @HttpCode(200)
  @ApiCookieAuth('refresh_cookie')
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
    @Res({ passthrough: true }) res: ExpressResponse,
  ): Promise<TokenResponseDto> {
    const { ip, userAgent } = extractRequestInfo(req);
    const result = await this.authService.login(dto, ip, userAgent);

    this.setAuthCookies(res, req, result.refreshToken);

    return new TokenResponseDto({
      accessToken: result.accessToken,
      jti: result.jti,
    });
  }

  @Get('csrf')
  @HttpCode(204)
  @SkipThrottle()
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
  @ApiCookieAuth('csrf_cookie')
  csrf(
    @Req() req: Request,
    @Res({ passthrough: true }) res: ExpressResponse,
  ): void {
    this.setCsrfCookie(res, req);
  }

  @Post('refresh')
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
  @ApiAuthLinks.refresh200()
  @ApiMutationErrorResponses({
    includeForbidden: false,
    includeConflict: false,
    unauthorizedDescription:
      'Refresh токен недійсний / відкликаний / reuse detected',
    unauthorizedMessageExample: 'Токен відкликано або недійсний',
  })
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: ExpressResponse,
  ): Promise<TokenResponseDto> {
    const { ip, userAgent } = extractRequestInfo(req);

    const refreshToken = getCookieString(req, 'refreshToken');
    if (!refreshToken) {
      throw new UnauthorizedException('Недійсний токен');
    }

    const result = await this.authService.refresh(refreshToken, ip, userAgent);

    // rotate BOTH refresh + csrf
    this.setAuthCookies(res, req, result.refreshToken);

    return new TokenResponseDto({
      accessToken: result.accessToken,
      jti: result.jti,
    });
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
    @Req() req: Request,
    @Res({ passthrough: true }) res: ExpressResponse,
  ): Promise<LogoutResponseDto> {
    const result = await this.authService.logout(userId);

    this.clearAuthCookies(res, req);

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
