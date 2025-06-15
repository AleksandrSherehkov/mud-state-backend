import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { AppLogger } from 'src/logger/logger.service';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  constructor(private readonly logger: AppLogger) {
    super();
    this.logger.setContext(PrismaService.name);
  }

  async onModuleInit() {
    this.logger.log('[PrismaService] Connecting to database...');

    await this.$connect();
  }

  async onModuleDestroy() {
    this.logger.log('[PrismaService] Disconnecting from database...');

    await this.$disconnect();
  }
}
