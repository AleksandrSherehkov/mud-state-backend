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

type RegisterResponse = {
  id: string;
  email: string;
  role: Role;
  createdAt: string;
  accessToken: string;
  refreshToken: string;
  jti: string;
};

type TerminateCountResponse = {
  terminatedCount: number;
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
    expect((v[k] as string).length).toBeGreaterThan(0);
  }
  expect(Number.isNaN(Date.parse(v.createdAt as string))).toBe(false);
}

function expectTerminateCountShape(
  value: unknown,
): asserts value is TerminateCountResponse {
  expect(value).toBeTruthy();
  expect(typeof value).toBe('object');
  const v = value as Record<string, unknown>;
  expect('terminatedCount' in v).toBe(true);
  expect(typeof v.terminatedCount).toBe('number');
  expect(Number.isFinite(v.terminatedCount)).toBe(true);
}

describe('Auth E2E — POST /auth/sessions/terminate-others', () => {
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

  it('401: without token -> Unauthorized', async () => {
    const res = await request(app.getHttpServer())
      .post(`${basePath}/auth/sessions/terminate-others`)
      .expect(401);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(401);
  });

  it('403: USER token -> Forbidden (RolesGuard)', async () => {
    const email = `user_${Date.now()}@e2e.local`;
    const password = 'strongPassword123';

    const regRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email, password })
      .expect(201);

    const regUnknown: unknown = regRes.body;
    expectRegisterResponseShape(regUnknown);
    const reg = regUnknown;

    const res = await request(app.getHttpServer())
      .post(`${basePath}/auth/sessions/terminate-others`)
      .set('Authorization', `Bearer ${reg.accessToken}`)
      .expect(403);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(403);
  });

  it('409: ADMIN with only current session -> Conflict "Немає інших активних сесій"', async () => {
    const password = 'strongPassword123';

    const adminEmail = `admin_${Date.now()}@e2e.local`;
    const regRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email: adminEmail, password })
      .expect(201);

    const regUnknown: unknown = regRes.body;
    expectRegisterResponseShape(regUnknown);
    const reg = regUnknown;

    await prisma.user.update({
      where: { id: reg.id },
      data: { role: Role.ADMIN },
    });

    const loginRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/login`)
      .send({ email: adminEmail, password })
      .expect(200);

    const token = loginRes.body as { accessToken: string };
    expect(typeof token.accessToken).toBe('string');

    const res = await request(app.getHttpServer())
      .post(`${basePath}/auth/sessions/terminate-others`)
      .set('Authorization', `Bearer ${token.accessToken}`)
      .expect(409);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(409);
  });

  it('200: ADMIN with 2 active sessions -> terminates others, keeps current sid active', async () => {
    const password = 'strongPassword123';

    const adminEmail = `admin2_${Date.now()}@e2e.local`;
    const regRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email: adminEmail, password })
      .expect(201);

    const regUnknown: unknown = regRes.body;
    expectRegisterResponseShape(regUnknown);
    const reg = regUnknown;

    await prisma.user.update({
      where: { id: reg.id },
      data: { role: Role.ADMIN },
    });

    const loginRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/login`)
      .send({ email: adminEmail, password })
      .expect(200);

    const token = loginRes.body as { accessToken: string };
    expect(typeof token.accessToken).toBe('string');

    const currentActive = await prisma.session.findFirst({
      where: { userId: reg.id, isActive: true },
      orderBy: { startedAt: 'desc' },
      select: { id: true, refreshTokenId: true },
    });
    expect(currentActive).toBeTruthy();

    await prisma.session.create({
      data: {
        userId: reg.id,
        refreshTokenId: currentActive!.refreshTokenId,
        ip: '127.0.0.2',
        userAgent: 'e2e-extra-session',
        isActive: true,
      },
    });

    const activeBefore = await prisma.session.count({
      where: { userId: reg.id, isActive: true },
    });
    expect(activeBefore).toBeGreaterThanOrEqual(2);

    const res = await request(app.getHttpServer())
      .post(`${basePath}/auth/sessions/terminate-others`)
      .set('Authorization', `Bearer ${token.accessToken}`)
      .expect(200);

    const bodyUnknown: unknown = res.body;
    expectTerminateCountShape(bodyUnknown);
    const body = bodyUnknown;

    expect(body.terminatedCount).toBeGreaterThanOrEqual(1);

    const activeAfter = await prisma.session.findMany({
      where: { userId: reg.id, isActive: true },
      select: { id: true },
    });

    expect(activeAfter.length).toBe(1);
    expect(activeAfter[0].id).toBe(currentActive!.id);
  });
});
