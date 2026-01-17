import {
  INestApplication,
  ValidationPipe,
  VersioningType,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { AppModule } from 'src/app.module';
import { PrismaService } from 'src/prisma/prisma.service';
import * as request from 'supertest';

import { Role } from '@prisma/client';

type TokenResponse = {
  accessToken: string;
  refreshToken: string;
  jti: string;
};

type RegisterResponse = {
  id: string;
  email: string;
  role: Role;
  createdAt: string;
  accessToken: string;
  refreshToken: string;
  jti: string;
};

type HttpErrorResponse = {
  statusCode: number;
  message: string | string[];
  error?: string;
};

function expectTokenResponseShape(
  value: unknown,
): asserts value is TokenResponse {
  expect(value).toBeTruthy();
  expect(typeof value).toBe('object');

  const v = value as Record<string, unknown>;

  expect('accessToken' in v).toBe(true);
  expect('refreshToken' in v).toBe(true);
  expect('jti' in v).toBe(true);

  expect(typeof v.accessToken).toBe('string');
  expect((v.accessToken as string).length).toBeGreaterThan(10);

  expect(typeof v.refreshToken).toBe('string');
  expect((v.refreshToken as string).length).toBeGreaterThan(10);

  expect(typeof v.jti).toBe('string');
  expect((v.jti as string).length).toBeGreaterThan(10);
}

describe('Auth E2E — login', () => {
  let app: INestApplication;
  let prisma: PrismaService;

  const API_PREFIX = process.env.API_PREFIX ?? 'api';
  const API_VERSION = process.env.API_VERSION ?? '1';
  const basePath = `/${API_PREFIX}/v${API_VERSION}`;

  beforeAll(async () => {
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

  it('200: login existing user -> returns tokens + jti', async () => {
    const email = `login_${Date.now()}@e2e.local`;
    const password = 'strongPassword123';

    const regRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email, password })
      .expect(201);

    const reg = regRes.body as RegisterResponse;
    expect(reg.email).toBe(email.toLowerCase());

    const loginRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/login`)
      .send({ email, password })
      .expect(200);

    const tokensUnknown: unknown = loginRes.body;
    expectTokenResponseShape(tokensUnknown);

    const tokens = tokensUnknown;

    expect(tokens.refreshToken).not.toBe(reg.refreshToken);
    expect(tokens.jti).not.toBe(reg.jti);
  });

  it('401: wrong password -> Unauthorized', async () => {
    const email = `wrongpw_${Date.now()}@e2e.local`;
    const password = 'strongPassword123';

    await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email, password })
      .expect(201);

    const res = await request(app.getHttpServer())
      .post(`${basePath}/auth/login`)
      .send({ email, password: 'wrongPassword123' })
      .expect(401);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(401);
    expect(
      typeof body.message === 'string' || Array.isArray(body.message),
    ).toBe(true);
  });

  it('400: invalid email -> Bad Request (validation)', async () => {
    const res = await request(app.getHttpServer())
      .post(`${basePath}/auth/login`)
      .send({ email: 'not-an-email', password: 'strongPassword123' })
      .expect(400);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(400);
    expect(Array.isArray(body.message)).toBe(true);
  });

  it('400: extra fields are forbidden (forbidNonWhitelisted)', async () => {
    const res = await request(app.getHttpServer())
      .post(`${basePath}/auth/login`)
      .send({
        email: `extra_${Date.now()}@e2e.local`,
        password: 'strongPassword123',
        role: Role.ADMIN,
      })
      .expect(400);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(400);
    expect(Array.isArray(body.message)).toBe(true);
  });
});
