import { Injectable, UnauthorizedException } from '@nestjs/common';
import type { Request, Response as ExpressResponse } from 'express';

import { AuthCookieService } from './auth-cookie.service';

import { extractRequestInfo } from 'src/common/http/request-info';
import { getRefreshTokenFromRequest } from 'src/common/http/refresh-token';

import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

import { RegisterResponseDto } from './dto/register-response.dto';
import { TokenResponseDto } from './dto/token-response.dto';
import { LogoutResponseDto } from './dto/logout-response.dto';
import { MeResponseDto } from './dto/me-response.dto';

import { RegisterUseCase } from './use-cases/register.use-case';
import { LoginUseCase } from './use-cases/login.use-case';
import { RefreshUseCase } from './use-cases/refresh.use-case';
import { LogoutUseCase } from './use-cases/logout.use-case';
import { GetMeUseCase } from './use-cases/get-me.use-case';

@Injectable()
export class AuthHttpService {
  constructor(
    private readonly registerUc: RegisterUseCase,
    private readonly loginUc: LoginUseCase,
    private readonly refreshUc: RefreshUseCase,
    private readonly logoutUc: LogoutUseCase,
    private readonly meUc: GetMeUseCase,
    private readonly cookies: AuthCookieService,
  ) {}

  async register(
    dto: RegisterDto,
    req: Request,
    res: ExpressResponse,
  ): Promise<RegisterResponseDto> {
    const { ip, userAgent, geo } = extractRequestInfo(req);

    const result = await this.registerUc.execute(dto, { ip, userAgent, geo });

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

  async login(
    dto: LoginDto,
    req: Request,
    res: ExpressResponse,
  ): Promise<TokenResponseDto> {
    const { ip, userAgent, geo } = extractRequestInfo(req);

    const result = await this.loginUc.execute(dto, { ip, userAgent, geo });

    this.cookies.setAuthCookies(res, req, result.refreshToken);

    return new TokenResponseDto({
      accessToken: result.accessToken,
      jti: result.jti,
    });
  }

  csrf(req: Request, res: ExpressResponse): void {
    this.cookies.setCsrfCookie(res, req);
  }

  async refresh(req: Request, res: ExpressResponse): Promise<TokenResponseDto> {
    const { ip, userAgent, geo } = extractRequestInfo(req);

    const refreshToken = getRefreshTokenFromRequest(req);
    if (!refreshToken) throw new UnauthorizedException('Недійсний токен');

    const result = await this.refreshUc.execute(refreshToken, {
      ip,
      userAgent,
      geo,
    });

    this.cookies.setRefreshCookie(res, req, result.refreshToken);

    return new TokenResponseDto({
      accessToken: result.accessToken,
      jti: result.jti,
    });
  }

  async logout(
    userId: string,
    req: Request,
    res: ExpressResponse,
  ): Promise<LogoutResponseDto> {
    const result = await this.logoutUc.execute(userId);

    this.cookies.clearAuthCookies(res, req);

    return new LogoutResponseDto({
      loggedOut: Boolean(result),
      terminatedAt: result?.terminatedAt ?? null,
    });
  }

  async getMe(userId: string): Promise<MeResponseDto> {
    const user = await this.meUc.execute(userId);
    return new MeResponseDto(user);
  }
}
