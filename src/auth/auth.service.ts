import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
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

  async register(dto: RegisterDto, ip?: string, userAgent?: string) {
    const user = await this.usersService.createUser(dto);
    const tokens = await this.generateTokens(
      user.id,
      user.email,
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

    await this.prisma.refreshToken.updateMany({
      where: {
        userId: user.id,
        revoked: false,
      },
      data: {
        revoked: true,
      },
    });

    await this.prisma.session.updateMany({
      where: {
        userId: user.id,
        isActive: true,
      },
      data: {
        isActive: false,
        endedAt: new Date(),
      },
    });

    return this.generateTokens(user.id, user.email, ip, userAgent);
  }

  async refresh(
    userId: string,
    refreshToken: string,
    ip?: string,
    userAgent?: string,
  ): Promise<Tokens> {
    let payload: JwtPayload & { jti: string };

    try {
      payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.config.get<string>('JWT_REFRESH_SECRET'),
      });
    } catch (err) {
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

    await this.prisma.session.updateMany({
      where: {
        refreshTokenId: payload.jti,
        endedAt: null,
      },
      data: {
        endedAt: new Date(),
        isActive: false,
      },
    });

    const user = await this.usersService.findById(userId);
    if (!user) throw new UnauthorizedException('Користувача не знайдено');

    return this.generateTokens(user.id, user.email, ip, userAgent);
  }

  async logout(userId: string): Promise<{ loggedOut: boolean }> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('Користувача не знайдено');
    }

    const [activeTokens, activeSessions] = await Promise.all([
      this.prisma.refreshToken.count({
        where: { userId, revoked: false },
      }),
      this.prisma.session.count({
        where: { userId, isActive: true },
      }),
    ]);

    if (activeTokens === 0 && activeSessions === 0) {
      throw new ConflictException('Користувач вже вийшов із системи');
    }

    await this.prisma.refreshToken.updateMany({
      where: { userId, revoked: false },
      data: { revoked: true },
    });

    await this.prisma.session.updateMany({
      where: { userId, isActive: true },
      data: {
        isActive: false,
        endedAt: new Date(),
      },
    });

    return { loggedOut: true };
  }

  private async generateTokens(
    userId: string,
    email: string,
    ip?: string,
    userAgent?: string,
  ): Promise<Tokens> {
    const refreshTokenId = randomUUID();
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new UnauthorizedException();
    const payload: JwtPayload = {
      sub: userId,
      email,
      jti: refreshTokenId,
      role: user.role,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.config.get<string>('JWT_ACCESS_SECRET'),
        expiresIn: this.config.get<string>('JWT_ACCESS_EXPIRES_IN', '15m'),
      }),
      this.jwtService.signAsync(payload, {
        secret: this.config.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: this.config.get<string>('JWT_REFRESH_EXPIRES_IN', '7d'),
      }),
    ]);

    await this.prisma.refreshToken.create({
      data: {
        userId,
        jti: refreshTokenId,
        ip,
        userAgent,
      },
    });

    await this.prisma.session.create({
      data: {
        userId,
        refreshTokenId,
        ip,
        userAgent,
      },
    });

    return { accessToken, refreshToken, jti: refreshTokenId };
  }
}
