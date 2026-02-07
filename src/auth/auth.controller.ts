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

import { Throttle } from '@nestjs/throttler';

import { TokenResponseDto } from './dto/token-response.dto';
import { MeResponseDto } from './dto/me-response.dto';
import { extractRequestInfo } from 'src/common/helpers/request-info';
import { LogoutResponseDto } from './dto/logout-response.dto';
import { RegisterResponseDto } from './dto/register-response.dto';
import { ApiRolesAccess } from 'src/common/swagger/api-roles';
import { AUTH_SIDE_EFFECTS } from 'src/common/swagger/auth.swagger';
import { ApiAuthLinks } from 'src/common/swagger/auth.links';
import { CsrfGuard } from 'src/common/guards/csrf.guard';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { CurrentUser } from 'src/common/decorators/current-user.decorator';
import { getRefreshTokenFromRequest } from 'src/common/http/refresh-token';
import { THROTTLE_AUTH } from 'src/common/throttle/throttle-env';
import { AuthCookieService } from './auth-cookie.service';

type CookieSameSite = 'lax' | 'strict' | 'none';

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
    private readonly cookies: AuthCookieService,
  ) {}

  @Post('register')
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
  async register(
    @Body() dto: RegisterDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: ExpressResponse,
  ): Promise<RegisterResponseDto> {
    const { ip, userAgent } = extractRequestInfo(req);

    const result = await this.authService.register(dto, ip, userAgent);

    this.cookies.setAuthCookies(res, req, result.refreshToken);

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
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: ExpressResponse,
  ): Promise<TokenResponseDto> {
    const { ip, userAgent } = extractRequestInfo(req);
    const result = await this.authService.login(dto, ip, userAgent);

    this.cookies.setAuthCookies(res, req, result.refreshToken);

    return new TokenResponseDto({
      accessToken: result.accessToken,
      jti: result.jti,
    });
  }

  @Get('csrf')
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
    this.cookies.setCsrfCookie(res, req);
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
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: ExpressResponse,
  ): Promise<TokenResponseDto> {
    const { ip, userAgent } = extractRequestInfo(req);

    const refreshToken = getRefreshTokenFromRequest(req);
    if (!refreshToken) {
      throw new UnauthorizedException('Недійсний токен');
    }

    const result = await this.authService.refresh(refreshToken, ip, userAgent);

    this.cookies.setRefreshCookie(res, req, result.refreshToken);

    return new TokenResponseDto({
      accessToken: result.accessToken,
      jti: result.jti,
    });
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard, CsrfGuard)
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
  async logout(
    @CurrentUser('userId') userId: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: ExpressResponse,
  ): Promise<LogoutResponseDto> {
    const result = await this.authService.logout(userId);

    this.cookies.clearAuthCookies(res, req);

    return new LogoutResponseDto({
      loggedOut: Boolean(result),
      terminatedAt: result?.terminatedAt ?? null,
    });
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
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
  async getMe(@CurrentUser('userId') userId: string): Promise<MeResponseDto> {
    const user = await this.authService.getMe(userId);
    return new MeResponseDto(user);
  }
}
