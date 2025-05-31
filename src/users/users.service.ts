import { Injectable, ConflictException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { User } from '@prisma/client';
import { CreateUserDto } from './dto/create-user.dto';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class UsersService {
  constructor(
    private prisma: PrismaService,
    private config: ConfigService,
  ) {}

  async createUser(dto: CreateUserDto): Promise<User> {
    const existing = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (existing) throw new ConflictException('Email already in use');

    const saltRounds = parseInt(
      this.config.get('BCRYPT_SALT_ROUNDS') || '10',
      10,
    );
    const hash = await bcrypt.hash(dto.password, saltRounds);

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
    return this.prisma.user.findUnique({
      where: { id },
    });
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
}
