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
import { useContainer } from 'class-validator';
import { buildValidPassword } from './helpers/password';

type RegisterResponse = {
  id: string;
  email: string;
  role: Role;
  createdAt: string;
  accessToken: string;
  refreshToken: string;
  jti: string;
};

type FullSessionResponse = {
  id: string;
  ip: string;
  userAgent: string;
  isActive: boolean;
  startedAt: string;
  endedAt: string | null;
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

function expectFullSessionsArrayShape(
  value: unknown,
): asserts value is FullSessionResponse[] {
  expect(Array.isArray(value)).toBe(true);

  for (const item of value as unknown[]) {
    expect(item).toBeTruthy();
    expect(typeof item).toBe('object');

    const v = item as Record<string, unknown>;

    for (const k of ['id', 'ip', 'userAgent', 'startedAt'] as const) {
      expect(k in v).toBe(true);
      expect(typeof v[k]).toBe('string');
    }

    expect('isActive' in v).toBe(true);
    expect(typeof v.isActive).toBe('boolean');

    expect('endedAt' in v).toBe(true);
    expect(v.endedAt === null || typeof v.endedAt === 'string').toBe(true);

    expect((v.id as string).length).toBeGreaterThan(0);
    expect(Number.isNaN(Date.parse(v.startedAt as string))).toBe(false);
    if (typeof v.endedAt === 'string') {
      expect(Number.isNaN(Date.parse(v.endedAt))).toBe(false);
    }
  }
}

function isSortedDescByStartedAt(list: FullSessionResponse[]) {
  for (let i = 1; i < list.length; i++) {
    const prev = Date.parse(list[i - 1].startedAt);
    const cur = Date.parse(list[i].startedAt);
    if (prev < cur) return false;
  }
  return true;
}

describe('Auth E2E — GET /auth/sessions/me', () => {
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
      .get(`${basePath}/auth/sessions/me`)
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
      .get(`${basePath}/auth/sessions/me`)
      .set('Authorization', `Bearer ${reg.accessToken}`)
      .expect(403);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(403);
  });

  it('200: ADMIN token -> returns all sessions of current user, sorted desc, includes endedAt for inactive', async () => {
    const password = buildValidPassword();
    const adminEmail = `admin_me_${Date.now()}@e2e.local`;

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
      select: { id: true, refreshTokenId: true },
    });

    expect(active).not.toBeNull();
    expect(active?.refreshTokenId).toEqual(expect.any(String));
    expect(active?.refreshTokenId?.length).toBeGreaterThan(0);

    const refreshTokenId = active!.refreshTokenId!;

    await prisma.session.create({
      data: {
        userId: reg.id,
        refreshTokenId,
        ip: '127.0.0.9',
        userAgent: 'e2e-ended',
        isActive: false,
        startedAt: new Date(Date.now() - 120_000),
        endedAt: new Date(Date.now() - 60_000),
      },
    });

    const res = await request(app.getHttpServer())
      .get(`${basePath}/auth/sessions/me`)
      .set('Authorization', `Bearer ${token.accessToken}`)
      .expect(200);

    const sessionsUnknown: unknown = res.body;
    expectFullSessionsArrayShape(sessionsUnknown);
    const sessions: FullSessionResponse[] = sessionsUnknown;

    expect(sessions.length).toBeGreaterThanOrEqual(1);
    expect(isSortedDescByStartedAt(sessions)).toBe(true);

    const ids = sessions.map((s) => s.id);
    const db = await prisma.session.findMany({
      where: { id: { in: ids } },
      select: { id: true, userId: true, isActive: true, endedAt: true },
    });

    expect(db.length).toBe(ids.length);
    for (const s of db) {
      expect(s.userId).toBe(reg.id);
    }

    const inactiveFromApi = sessions.find((s) => s.isActive === false);
    expect(inactiveFromApi).toBeTruthy();
    expect(inactiveFromApi!.endedAt).not.toBeNull();

    const activeFromApi = sessions.find((s) => s.isActive === true);
    expect(activeFromApi).toBeTruthy();
    expect(activeFromApi!.endedAt).toBeNull();
  });
});
