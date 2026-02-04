import { Injectable } from '@nestjs/common';

import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuthTransactionService {
  constructor(private readonly prisma: PrismaService) {}

  run<T>(fn: (tx: unknown) => Promise<T>): Promise<T> {
    return this.prisma.$transaction((tx) => fn(tx as unknown));
  }
}
