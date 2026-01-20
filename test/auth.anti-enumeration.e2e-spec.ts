import {
  INestApplication,
  ValidationPipe,
  VersioningType,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as request from 'supertest';

import { PrismaService } from 'src/prisma/prisma.service';
import { buildValidPassword } from './helpers/password';
import { useContainer } from 'class-validator';

type HttpErrorResponse = {
  statusCode: number;
  message: string | string[];
  error?: string;
};

describe('Auth E2E — anti-enumeration (same 401 for not-found vs wrong-password)', () => {
  let app: INestApplication;
  let prisma: PrismaService;

  const API_PREFIX = process.env.API_PREFIX ?? 'api';
  const API_VERSION = process.env.API_VERSION ?? '1';
  const basePath = `/${API_PREFIX}/v${API_VERSION}`;

  beforeAll(async () => {
    process.env.APP_ENV = 'test';
    process.env.NODE_ENV = 'test';

    process.env.THROTTLE_TTL = '60';
    process.env.THROTTLE_LIMIT = '100';

    const { AppModule } = await import('src/app.module');

    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();

    app.setGlobalPrefix(API_PREFIX);
    app.enableVersioning({
      type: VersioningType.URI,
      defaultVersion: API_VERSION,
    });

    app.useGlobalPipes(
      new ValidationPipe({
        transform: true,
        whitelist: true,
        forbidNonWhitelisted: true,
      }),
    );
    useContainer(app.select(AppModule), { fallbackOnErrors: true });
    await app.init();
    prisma = app.get(PrismaService);
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(async () => {
    await prisma.user.deleteMany({
      where: { email: { endsWith: '@e2e.local' } },
    });
  });

  it('returns identical 401 JSON body for (a) missing user and (b) wrong password', async () => {
    const existingEmail = `exist_${Date.now()}@e2e.local`;
    const password = buildValidPassword();

    await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email: existingEmail, password })
      .expect(201);

    const missingEmail = `missing_${Date.now()}@e2e.local`;

    const resMissing = await request(app.getHttpServer())
      .post(`${basePath}/auth/login`)
      .send({ email: missingEmail, password })
      .expect(401);

    const resWrongPw = await request(app.getHttpServer())
      .post(`${basePath}/auth/login`)
      .send({ email: existingEmail, password: 'wrongPassword123' })
      .expect(401);

    const a = resMissing.body as HttpErrorResponse;
    const b = resWrongPw.body as HttpErrorResponse;

    expect(a.statusCode).toBe(401);
    expect(b.statusCode).toBe(401);

    expect(a).toEqual(b);

    expect(typeof a.message).toBe('string');
  });
});
