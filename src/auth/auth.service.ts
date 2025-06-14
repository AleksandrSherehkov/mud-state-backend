import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

import * as bcrypt from 'bcrypt';
import { Tokens, JwtPayload } from './types/jwt.types';
import { randomUUID } from 'crypto';
import { TokenService } from './token.service';
import { RefreshTokenService } from './refresh-token.service';
import { SessionService } from './session.service';
import { Role } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private tokenService: TokenService,
    private refreshTokenService: RefreshTokenService,
    private sessionService: SessionService,
  ) {}

  async register(dto: RegisterDto, ip?: string, userAgent?: string) {
    const user = await this.usersService.createUser(dto);
    const tokens = await this.issueTokens(
      user.id,
      user.email,
      user.role,
      ip,
      userAgent,
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
    userAgent?: string,
  ): Promise<Tokens> {
    let payload: JwtPayload & { jti: string };

    try {
      payload = await this.tokenService.verifyRefreshToken(refreshToken);
    } catch {
      throw new UnauthorizedException('Недійсний токен');
    }

    const token = await this.refreshTokenService.findValid(userId, payload.jti);
    if (!token || token.userId !== userId) {
      throw new UnauthorizedException(
        'Підозрілий токен або невідповідність користувача',
      );
    }

    const user = await this.usersService.findById(userId);
    if (!user) throw new UnauthorizedException('Користувача не знайдено');

    const tokens = await this.issueTokens(
      user.id,
      user.email,
      user.role,
      ip,
      userAgent,
    );

    await this.refreshTokenService.revokeByJti(payload.jti);
    await this.sessionService.terminateByRefreshToken(payload.jti);

    return tokens;
  }

  async logout(userId: string): Promise<{ loggedOut: boolean }> {
    const user = await this.usersService.findById(userId);
    if (!user) throw new NotFoundException('Користувача не знайдено');

    const [activeTokens, activeSessions] = await Promise.all([
      this.refreshTokenService.countActive(userId),
      this.sessionService.countActive(userId),
    ]);

    if (!activeTokens && !activeSessions) {
      throw new ConflictException('Користувач вже вийшов із системи');
    }

    await Promise.all([
      this.refreshTokenService.revokeAll(userId),
      this.sessionService.terminateAll(userId),
    ]);

    return { loggedOut: true };
  }

  private async issueTokens(
    userId: string,
    email: string,
    role: Role,
    ip?: string,
    userAgent?: string,
  ): Promise<Tokens> {
    const refreshTokenId = randomUUID();

    await this.refreshTokenService.create(
      userId,
      refreshTokenId,
      ip,
      userAgent,
    );
    const session = await this.sessionService.create(
      userId,
      refreshTokenId,
      ip,
      userAgent,
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
