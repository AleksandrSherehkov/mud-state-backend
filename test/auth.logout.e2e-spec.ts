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
import { buildValidPassword } from './helpers/password';
import { useContainer } from 'class-validator';

type RegisterResponse = {
  id: string;
  email: string;
  role: Role;
  createdAt: string;
  accessToken: string;
  refreshToken: string;
  jti: string;
};

type LogoutResponse = {
  loggedOut: boolean;
  terminatedAt: string | null;
};

type HttpErrorResponse = {
  statusCode: number;
  message: string | string[];
  error?: string;
};

function expectRegisterResponseShape(
  value: unknown,
): asserts value is RegisterResponse {
  expect(value).toBeTruthy();
  expect(typeof value).toBe('object');

  const v = value as Record<string, unknown>;

  for (const k of [
    'id',
    'email',
    'role',
    'createdAt',
    'accessToken',
    'refreshToken',
    'jti',
  ] as const) {
    expect(k in v).toBe(true);
    expect(typeof v[k]).toBe('string');
  }
}

function expectLogoutResponseShape(
  value: unknown,
): asserts value is LogoutResponse {
  expect(value).toBeTruthy();
  expect(typeof value).toBe('object');

  const v = value as Record<string, unknown>;

  expect('loggedOut' in v).toBe(true);
  expect(typeof v.loggedOut).toBe('boolean');
  expect(v.loggedOut).toBe(true);

  expect('terminatedAt' in v).toBe(true);
  expect(v.terminatedAt === null || typeof v.terminatedAt === 'string').toBe(
    true,
  );
}

describe('Auth E2E — logout', () => {
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

  it('401: logout without token -> Unauthorized', async () => {
    const res = await request(app.getHttpServer())
      .post(`${basePath}/auth/logout`)
      .expect(401);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(401);
    expect(
      typeof body.message === 'string' || Array.isArray(body.message),
    ).toBe(true);
  });

  it('200: logout with accessToken -> ok, then refresh must be 401', async () => {
    const email = `logout_${Date.now()}@e2e.local`;
    const password = buildValidPassword();

    const regRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email, password })
      .expect(201);

    const regUnknown: unknown = regRes.body;
    expectRegisterResponseShape(regUnknown);
    const reg: RegisterResponse = regUnknown;

    const logoutRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/logout`)
      .set('Authorization', `Bearer ${reg.accessToken}`)
      .expect(200);

    const logoutBodyUnknown: unknown = logoutRes.body;
    expectLogoutResponseShape(logoutBodyUnknown);

    const refreshRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/refresh`)
      .send({ userId: reg.id, refreshToken: reg.refreshToken })
      .expect(401);

    const refreshBody = refreshRes.body as HttpErrorResponse;
    expect(refreshBody.statusCode).toBe(401);
    expect(
      typeof refreshBody.message === 'string' ||
        Array.isArray(refreshBody.message),
    ).toBe(true);
  });

  it('401: second logout with the same accessToken -> Unauthorized (token invalidated by logout)', async () => {
    const email = `logout2_${Date.now()}@e2e.local`;
    const password = buildValidPassword();

    const regRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email, password })
      .expect(201);

    const regUnknown: unknown = regRes.body;
    expectRegisterResponseShape(regUnknown);
    const reg: RegisterResponse = regUnknown;

    await request(app.getHttpServer())
      .post(`${basePath}/auth/logout`)
      .set('Authorization', `Bearer ${reg.accessToken}`)
      .expect(200);

    const second = await request(app.getHttpServer())
      .post(`${basePath}/auth/logout`)
      .set('Authorization', `Bearer ${reg.accessToken}`)
      .expect(401);

    const body = second.body as HttpErrorResponse;
    expect(body.statusCode).toBe(401);
    expect(
      typeof body.message === 'string' || Array.isArray(body.message),
    ).toBe(true);
  });
});
