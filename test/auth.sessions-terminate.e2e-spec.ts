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

type TerminateResultResponse = { terminated: boolean };

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

function expectTerminateResultShape(
  value: unknown,
): asserts value is TerminateResultResponse {
  expect(value).toBeTruthy();
  expect(typeof value).toBe('object');
  const v = value as Record<string, unknown>;
  expect('terminated' in v).toBe(true);
  expect(typeof v.terminated).toBe('boolean');
}

describe('Auth E2E — POST /auth/sessions/terminate', () => {
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
      .post(`${basePath}/auth/sessions/terminate`)
      .send({ ip: '127.0.0.1', userAgent: 'ua' })
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
    const reg: RegisterResponse = regUnknown;

    const res = await request(app.getHttpServer())
      .post(`${basePath}/auth/sessions/terminate`)
      .set('Authorization', `Bearer ${reg.accessToken}`)
      .send({ ip: '127.0.0.1', userAgent: 'ua' })
      .expect(403);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(403);
  });

  it('200: ADMIN -> terminates matching active session by ip+userAgent', async () => {
    const password = 'strongPassword123';
    const adminEmail = `admin_term_${Date.now()}@e2e.local`;

    const regRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email: adminEmail, password })
      .expect(201);

    const regUnknown: unknown = regRes.body;
    expectRegisterResponseShape(regUnknown);
    const reg: RegisterResponse = regUnknown;

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
    expect(token.accessToken.length).toBeGreaterThan(10);

    const active = await prisma.session.findFirst({
      where: { userId: reg.id, isActive: true },
      orderBy: { startedAt: 'desc' },
      select: { refreshTokenId: true },
    });

    expect(active).not.toBeNull();
    expect(active?.refreshTokenId).toEqual(expect.any(String));
    expect(active?.refreshTokenId?.length).toBeGreaterThan(0);
    const refreshTokenId = active!.refreshTokenId!;

    const targetIp = '127.0.0.2';
    const targetUa = 'e2e-target-ua';

    const targetSession = await prisma.session.create({
      data: {
        userId: reg.id,
        refreshTokenId,
        ip: targetIp,
        userAgent: targetUa,
        isActive: true,
        startedAt: new Date(Date.now() - 60_000),
      },
      select: { id: true },
    });

    const res = await request(app.getHttpServer())
      .post(`${basePath}/auth/sessions/terminate`)
      .set('Authorization', `Bearer ${token.accessToken}`)
      .send({
        ip: `  ${targetIp}  `,
        userAgent: ` ${targetUa} `,
      })
      .expect(200);

    const bodyUnknown: unknown = res.body;
    expectTerminateResultShape(bodyUnknown);
    const body: TerminateResultResponse = bodyUnknown;

    expect(body.terminated).toBe(true);

    const db = await prisma.session.findUnique({
      where: { id: targetSession.id },
      select: { isActive: true, endedAt: true },
    });

    expect(db).not.toBeNull();
    expect(db!.isActive).toBe(false);
    expect(db!.endedAt).not.toBeNull();
  });

  it('200: ADMIN -> returns terminated=false when no matching active session', async () => {
    const password = 'strongPassword123';
    const adminEmail = `admin_term_none_${Date.now()}@e2e.local`;

    const regRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email: adminEmail, password })
      .expect(201);

    const regUnknown: unknown = regRes.body;
    expectRegisterResponseShape(regUnknown);
    const reg: RegisterResponse = regUnknown;

    await prisma.user.update({
      where: { id: reg.id },
      data: { role: Role.ADMIN },
    });

    const loginRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/login`)
      .send({ email: adminEmail, password })
      .expect(200);

    const token = loginRes.body as { accessToken: string };

    const res = await request(app.getHttpServer())
      .post(`${basePath}/auth/sessions/terminate`)
      .set('Authorization', `Bearer ${token.accessToken}`)
      .send({ ip: '10.10.10.10', userAgent: 'nope' })
      .expect(200);

    const bodyUnknown: unknown = res.body;
    expectTerminateResultShape(bodyUnknown);
    const body: TerminateResultResponse = bodyUnknown;

    expect(body.terminated).toBe(false);
  });
});
