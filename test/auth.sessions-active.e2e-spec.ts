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

type ActiveSessionResponse = {
  id: string;
  ip: string;
  userAgent: string;
  startedAt: string;
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

function expectActiveSessionsArrayShape(
  value: unknown,
): asserts value is ActiveSessionResponse[] {
  expect(Array.isArray(value)).toBe(true);

  for (const item of value as unknown[]) {
    expect(item).toBeTruthy();
    expect(typeof item).toBe('object');

    const v = item as Record<string, unknown>;
    for (const k of ['id', 'ip', 'userAgent', 'startedAt'] as const) {
      expect(k in v).toBe(true);
      expect(typeof v[k]).toBe('string');
    }

    expect((v.id as string).length).toBeGreaterThan(0);
    expect(Number.isNaN(Date.parse(v.startedAt as string))).toBe(false);
  }
}

function isSortedDescByStartedAt(list: ActiveSessionResponse[]) {
  for (let i = 1; i < list.length; i++) {
    const prev = Date.parse(list[i - 1].startedAt);
    const cur = Date.parse(list[i].startedAt);
    if (prev < cur) return false;
  }
  return true;
}

describe('Auth E2E — GET /auth/sessions/active', () => {
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

  it('401: without token -> Unauthorized', async () => {
    const res = await request(app.getHttpServer())
      .get(`${basePath}/auth/sessions/active`)
      .expect(401);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(401);
  });

  it('403: USER token -> Forbidden (RolesGuard)', async () => {
    const email = `user_${Date.now()}@e2e.local`;
    const password = buildValidPassword();

    const regRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email, password })
      .expect(201);

    const regUnknown: unknown = regRes.body;
    expectRegisterResponseShape(regUnknown);
    const reg: RegisterResponse = regUnknown;

    const res = await request(app.getHttpServer())
      .get(`${basePath}/auth/sessions/active`)
      .set('Authorization', `Bearer ${reg.accessToken}`)
      .expect(403);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(403);
  });

  it('200: ADMIN token -> returns ONLY admin active sessions, sorted desc', async () => {
    const password = buildValidPassword();

    const adminEmail = `admin_${Date.now()}@e2e.local`;
    const adminRegRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email: adminEmail, password })
      .expect(201);

    const adminUnknown: unknown = adminRegRes.body;
    expectRegisterResponseShape(adminUnknown);
    const adminReg: RegisterResponse = adminUnknown;

    await prisma.user.update({
      where: { id: adminReg.id },
      data: { role: Role.ADMIN },
    });

    const adminLoginRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/login`)
      .send({ email: adminEmail, password })
      .expect(200);

    const adminToken = adminLoginRes.body as { accessToken: string };
    expect(typeof adminToken.accessToken).toBe('string');
    expect(adminToken.accessToken.length).toBeGreaterThan(10);

    const otherEmail = `other_${Date.now()}@e2e.local`;
    await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email: otherEmail, password })
      .expect(201);

    const res = await request(app.getHttpServer())
      .get(`${basePath}/auth/sessions/active`)
      .set('Authorization', `Bearer ${adminToken.accessToken}`)
      .expect(200);

    const sessionsUnknown: unknown = res.body;
    expectActiveSessionsArrayShape(sessionsUnknown);
    const sessions: ActiveSessionResponse[] = sessionsUnknown;

    expect(sessions.length).toBeGreaterThanOrEqual(1);
    expect(isSortedDescByStartedAt(sessions)).toBe(true);

    const ids = sessions.map((s) => s.id);
    const dbSessions = await prisma.session.findMany({
      where: { id: { in: ids } },
      select: { id: true, userId: true, isActive: true },
    });

    expect(dbSessions.length).toBe(ids.length);
    for (const s of dbSessions) {
      expect(s.userId).toBe(adminReg.id);
      expect(s.isActive).toBe(true);
    }
  });

  it('200: ADMIN token + limit=1 -> at most 1 item', async () => {
    const password = buildValidPassword();
    const adminEmail = `admin_limit_${Date.now()}@e2e.local`;

    const regRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email: adminEmail, password })
      .expect(201);

    const adminUnknown: unknown = regRes.body;
    expectRegisterResponseShape(adminUnknown);
    const adminReg: RegisterResponse = adminUnknown;

    await prisma.user.update({
      where: { id: adminReg.id },
      data: { role: Role.ADMIN },
    });

    const loginRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/login`)
      .send({ email: adminEmail, password })
      .expect(200);

    const adminToken = loginRes.body as { accessToken: string };

    const res = await request(app.getHttpServer())
      .get(`${basePath}/auth/sessions/active?limit=1`)
      .set('Authorization', `Bearer ${adminToken.accessToken}`)
      .expect(200);

    const sessionsUnknown: unknown = res.body;
    expectActiveSessionsArrayShape(sessionsUnknown);
    const sessions: ActiveSessionResponse[] = sessionsUnknown;

    expect(sessions.length).toBeLessThanOrEqual(1);
  });

  it('200: ADMIN token + limit=9999 -> clamped to <= 100', async () => {
    const password = buildValidPassword();
    const adminEmail = `admin_cap_${Date.now()}@e2e.local`;

    const regRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email: adminEmail, password })
      .expect(201);

    const adminUnknown: unknown = regRes.body;
    expectRegisterResponseShape(adminUnknown);
    const adminReg: RegisterResponse = adminUnknown;

    await prisma.user.update({
      where: { id: adminReg.id },
      data: { role: 'ADMIN' },
    });

    const loginRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/login`)
      .send({ email: adminEmail, password })
      .expect(200);

    const adminToken = loginRes.body as { accessToken: string };

    const res = await request(app.getHttpServer())
      .get(`${basePath}/auth/sessions/active?limit=9999`)
      .set('Authorization', `Bearer ${adminToken.accessToken}`)
      .expect(200);

    const sessionsUnknown: unknown = res.body;
    expectActiveSessionsArrayShape(sessionsUnknown);
    const sessions: ActiveSessionResponse[] = sessionsUnknown;

    expect(sessions.length).toBeLessThanOrEqual(100);
  });
});
