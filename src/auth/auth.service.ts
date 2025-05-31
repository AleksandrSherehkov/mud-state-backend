import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { Tokens, JwtPayload } from './types/jwt.types';
import { randomUUID } from 'crypto';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private config: ConfigService,
    private prisma: PrismaService,
  ) {}

  async register(dto: RegisterDto) {
    const user = await this.usersService.createUser(dto);
    const tokens = await this.generateTokens(user.id, user.email);

    return { ...user, ...tokens };
  }

  async login(dto: LoginDto): Promise<Tokens> {
    const user = await this.usersService.findByEmail(dto.email);
    if (!user) throw new UnauthorizedException('Невірний email або пароль');

    const isValid = await bcrypt.compare(dto.password, user.password);
    if (!isValid) throw new UnauthorizedException('Невірний email або пароль');

    const tokens = await this.generateTokens(user.id, user.email);

    return tokens;
  }

  async refresh(userId: string, refreshToken: string): Promise<Tokens> {
    let payload: JwtPayload & { jti: string };

    try {
      payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.config.get<string>('JWT_REFRESH_SECRET'),
      });
    } catch (err) {
      console.error('Помилка при перевірці токена:', err);
      throw new UnauthorizedException('Недійсний токен');
    }

    const tokenInDb = await this.prisma.refreshToken.findUnique({
      where: { jti: payload.jti },
    });

    if (!tokenInDb || tokenInDb.revoked || tokenInDb.userId !== userId) {
      throw new UnauthorizedException('Токен відкликано або недійсний');
    }

    await this.prisma.refreshToken.update({
      where: { jti: payload.jti },
      data: { revoked: true },
    });

    const user = await this.usersService.findById(userId);
    if (!user) throw new UnauthorizedException('Користувача не знайдено');

    const {
      accessToken,
      refreshToken: newRefreshToken,
      jti: newJti,
    } = await this.generateTokens(user.id, user.email);

    await this.prisma.refreshToken.create({
      data: {
        jti: newJti,
        userId: user.id,
      },
    });

    return { accessToken, refreshToken: newRefreshToken, jti: newJti };
  }

  async logout(userId: string): Promise<void> {
    await this.prisma.refreshToken.updateMany({
      where: {
        userId,
        revoked: false,
      },
      data: {
        revoked: true,
      },
    });
  }

  private async generateTokens(userId: string, email: string): Promise<Tokens> {
    const refreshTokenId = randomUUID();
    const payload: JwtPayload = { sub: userId, email, jti: refreshTokenId };
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.config.get<string>('JWT_ACCESS_SECRET'),
        expiresIn: this.config.get<string>('JWT_ACCESS_EXPIRES_IN', '15m'),
      }),
      this.jwtService.signAsync(payload, {
        secret: this.config.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: this.config.get<string>('JWT_ACCESS_EXPIRES_IN', '7d'),
      }),
    ]);

    await this.usersService.saveRefreshTokenEntry(userId, refreshTokenId);

    return { accessToken, refreshToken, jti: refreshTokenId };
  }
}
