import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

import * as bcrypt from 'bcrypt';
import { Tokens, JwtPayload } from './types/jwt.types';
import { randomUUID } from 'node:crypto';
import { TokenService } from './token.service';
import { RefreshTokenService } from './refresh-token.service';
import { SessionService } from './session.service';
import { Role } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly tokenService: TokenService,
    private readonly refreshTokenService: RefreshTokenService,
    private readonly sessionService: SessionService
  ) {}

  async register(dto: RegisterDto, ip?: string, userAgent?: string) {
    const user = await this.usersService.createUser(dto);
    const tokens = await this.issueTokens(
      user.id,
      user.email,
      user.role,
      ip,
      userAgent
    );
    return { ...user, ...tokens };
  }

  async login(dto: LoginDto, ip: string, userAgent: string): Promise<Tokens> {
    const user = await this.usersService.findByEmail(dto.email);
    if (!user) throw new UnauthorizedException('Невірний email або пароль');

    const isValid = await bcrypt.compare(dto.password, user.password);
    if (!isValid) throw new UnauthorizedException('Невірний email або пароль');

    await Promise.all([
      this.refreshTokenService.revokeAll(user.id),
      this.sessionService.terminateAll(user.id),
    ]);

    return this.issueTokens(user.id, user.email, user.role, ip, userAgent);
  }

  async refresh(
    userId: string,
    refreshToken: string,
    ip?: string,
    userAgent?: string
  ): Promise<Tokens> {
    let payload: JwtPayload & { jti: string };

    try {
      payload = await this.tokenService.verifyRefreshToken(refreshToken);
    } catch {
      throw new UnauthorizedException('Недійсний токен');
    }

    if (payload.sub !== userId) {
      throw new UnauthorizedException('Невідповідність користувача');
    }

    const claim = await this.refreshTokenService.revokeIfActive(
      payload.jti,
      userId
    );
    if (claim.count === 0) {
      throw new UnauthorizedException('Токен відкликано або недійсний');
    }

    await this.sessionService.terminateByRefreshToken(payload.jti);

    const user = await this.usersService.findById(userId);
    if (!user) throw new UnauthorizedException('Користувача не знайдено');

    return this.issueTokens(user.id, user.email, user.role, ip, userAgent);
  }

  async logout(
    userId: string
  ): Promise<{ loggedOut: true; terminatedAt: string } | null> {
    const user = await this.usersService.findById(userId);
    if (!user) throw new NotFoundException('Користувача не знайдено');

    const [revokeResult, terminateResult] = await Promise.all([
      this.refreshTokenService.revokeAll(userId),
      this.sessionService.terminateAll(userId),
    ]);

    if (revokeResult.count === 0 && terminateResult.count === 0) {
      return null;
    }

    return { loggedOut: true, terminatedAt: new Date().toISOString() };
  }

  private async issueTokens(
    userId: string,
    email: string,
    role: Role,
    ip?: string,
    userAgent?: string
  ): Promise<Tokens> {
    const refreshTokenId = randomUUID();

    await this.refreshTokenService.create(
      userId,
      refreshTokenId,
      ip,
      userAgent
    );
    const session = await this.sessionService.create(
      userId,
      refreshTokenId,
      ip,
      userAgent
    );

    const payload: JwtPayload = {
      sub: userId,
      email,
      jti: refreshTokenId,
      role,
      sid: session.id,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.tokenService.signAccessToken(payload),
      this.tokenService.signRefreshToken(payload),
    ]);

    return { accessToken, refreshToken, jti: refreshTokenId };
  }
}
