import {
  Injectable,
  ConflictException,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { Prisma, User } from '@prisma/client';
import { CreateUserDto } from './dto/create-user.dto';
import { ConfigService } from '@nestjs/config';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UsersService {
  constructor(
    private prisma: PrismaService,
    private config: ConfigService,
  ) {}

  private async hashPassword(password: string): Promise<string> {
    const saltRounds = parseInt(
      this.config.get('BCRYPT_SALT_ROUNDS') || '10',
      10,
    );
    return bcrypt.hash(password, saltRounds);
  }

  async createUser(dto: CreateUserDto): Promise<User> {
    const existing = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (existing)
      throw new ConflictException('Електронна адреса вже використовується');

    const hash = await this.hashPassword(dto.password);

    return this.prisma.user.create({
      data: {
        email: dto.email,
        password: hash,
      },
    });
  }

  async saveRefreshTokenEntry(userId: string, jti: string) {
    await this.prisma.refreshToken.create({
      data: {
        userId,
        jti,
      },
    });
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.prisma.user.findUnique({ where: { email } });
  }

  async findById(id: string): Promise<User | null> {
    return this.prisma.user.findUnique({ where: { id } });
  }

  async updateUser(id: string, dto: UpdateUserDto): Promise<User> {
    const { email, password, role } = dto;
    const data: Partial<User> = {};

    if (email) data.email = email;
    if (role) data.role = role;

    if (password) data.password = await this.hashPassword(password);

    try {
      return await this.prisma.user.update({
        where: { id },
        data,
      });
    } catch (err: unknown) {
      if (err instanceof Prisma.PrismaClientKnownRequestError) {
        if (err.code === 'P2002')
          throw new ConflictException('Email вже використовується');
        if (err.code === 'P2025')
          throw new NotFoundException('Користувача не знайдено');
      }
      throw err;
    }
  }

  async deleteUser(id: string): Promise<User> {
    try {
      return await this.prisma.user.delete({
        where: { id },
      });
    } catch (err: unknown) {
      if (
        err instanceof Prisma.PrismaClientKnownRequestError &&
        err.code === 'P2025'
      ) {
        throw new NotFoundException('Користувача не знайдено');
      }
      throw err;
    }
  }

  async cleanRevokedTokens(olderThanDays = 7): Promise<number> {
    const dateThreshold = new Date();
    dateThreshold.setDate(dateThreshold.getDate() - olderThanDays);

    const result = await this.prisma.refreshToken.deleteMany({
      where: {
        revoked: true,
        createdAt: { lt: dateThreshold },
      },
    });

    return result.count;
  }

  async cleanInactiveSessions(olderThanDays = 7): Promise<number> {
    const dateThreshold = new Date();
    dateThreshold.setDate(dateThreshold.getDate() - olderThanDays);

    const result = await this.prisma.session.deleteMany({
      where: {
        isActive: false,
        endedAt: { lt: dateThreshold },
      },
    });

    return result.count;
  }
}
