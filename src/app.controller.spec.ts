import 'reflect-metadata';
import { Test } from '@nestjs/testing';
import { PrismaService } from './prisma/prisma.service';
import { AppLogger } from './logger/logger.service';

// ✅ ключ: подменяем класс, который используется в APP_GUARD (useClass)
jest.mock('./common/guards/auth-throttler.guard', () => {
  class MockAuthThrottlerGuard {
    canActivate() {
      return true;
    }
  }
  return { AuthThrottlerGuard: MockAuthThrottlerGuard };
});

jest.mock('./auth/guards/roles.guard', () => {
  class MockRolesGuard {
    canActivate() {
      return true;
    }
  }
  return { RolesGuard: MockRolesGuard };
});

jest.mock('@nestjs/schedule', () => {
  const actual =
    jest.requireActual<typeof import('@nestjs/schedule')>('@nestjs/schedule');

  class MockScheduleModule {}

  return {
    ...actual,
    ScheduleModule: {
      ...actual.ScheduleModule,
      forRoot: () => ({
        global: true,
        module: MockScheduleModule,
        providers: [
          {
            provide: actual.SchedulerRegistry,
            useValue: {
              addCronJob: jest.fn(),
              deleteCronJob: jest.fn(),
              getCronJob: jest.fn(),
              getCronJobs: jest.fn(() => new Map()),
            },
          },
        ],
        exports: [actual.SchedulerRegistry],
      }),
    },
  };
});

describe('AppModule (smoke)', () => {
  beforeEach(() => {
    jest.resetModules();

    process.env.APP_ENV = 'test';
    process.env.DATABASE_URL =
      'postgresql://user:pass@localhost:5432/testdb?schema=public';
    process.env.JWT_ACCESS_SECRET = 'test_access_secret';
    process.env.JWT_REFRESH_SECRET = 'test_refresh_secret';
    process.env.JWT_ISSUER = 'mud-state-backend';
    process.env.JWT_AUDIENCE = 'mud-state-clients';
    process.env.REFRESH_TOKEN_PEPPER =
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  });

  it('should compile AppModule', async () => {
    const { AppModule } = await import('./app.module');

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
