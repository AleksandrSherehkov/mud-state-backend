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
  constructor(private readonly logger: Logger) {
    super();
  }

  async onModuleInit() {
    this.logger.log('[PrismaService] Connecting to database...');

    await this.$connect();
  }

  async onModuleDestroy() {
    this.logger.log('[PrismaService] Disconnecting to database...');

    await this.$disconnect();
  }
}
