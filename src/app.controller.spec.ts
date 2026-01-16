import 'reflect-metadata';
import { Test } from '@nestjs/testing';
import { AppModule } from './app.module';
import { PrismaService } from './prisma/prisma.service';
import { AppLogger } from './logger/logger.service';

describe('AppModule (smoke)', () => {
  beforeAll(() => {
    process.env.APP_ENV = 'test';
    process.env.DATABASE_URL =
      'postgresql://user:pass@localhost:5432/testdb?schema=public';
    process.env.JWT_ACCESS_SECRET = 'test_access_secret';
    process.env.JWT_REFRESH_SECRET = 'test_refresh_secret';
  });

  it('should compile AppModule', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    })

      .overrideProvider(PrismaService)
      .useValue({
        $connect: jest.fn().mockResolvedValue(undefined),
        $disconnect: jest.fn().mockResolvedValue(undefined),
      })

      .overrideProvider(AppLogger)
      .useValue({
        setContext: jest.fn(),
        log: jest.fn(),
        error: jest.fn(),
        warn: jest.fn(),
        debug: jest.fn(),
        verbose: jest.fn(),
      })
      .compile();

    expect(moduleRef).toBeDefined();
  });
});
