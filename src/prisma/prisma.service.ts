import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(PrismaService.name);

  constructor() {
    super();
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
