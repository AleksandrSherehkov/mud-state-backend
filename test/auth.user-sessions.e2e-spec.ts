import {
  INestApplication,
  ValidationPipe,
  VersioningType,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { AppModule } from 'src/app.module';
import { PrismaService } from 'src/prisma/prisma.service';
import * as request from 'supertest';
import { RequestIdInterceptor } from 'src/common/request-context/request-id.interceptor';
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

type HttpErrorResponse = {
  statusCode: number;
  message: string | string[];
  error?: string;
};

type RefreshTokenSessionResponse = {
  jti: string;
  ip: string;
  userAgent: string;
  createdAt: string;
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

function expectSessionsArrayShape(
  value: unknown,
): asserts value is RefreshTokenSessionResponse[] {
  expect(Array.isArray(value)).toBe(true);

  for (const item of value as unknown[]) {
    expect(item).toBeTruthy();
    expect(typeof item).toBe('object');

    const v = item as Record<string, unknown>;

    for (const k of ['jti', 'ip', 'userAgent', 'createdAt'] as const) {
      expect(k in v).toBe(true);
      expect(typeof v[k]).toBe('string');
    }

    expect((v.jti as string).length).toBeGreaterThan(0);
    expect(Number.isNaN(Date.parse(v.createdAt as string))).toBe(false);
  }
}

describe('Auth E2E — GET /auth/:userId/sessions', () => {
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

    app.useGlobalInterceptors(new RequestIdInterceptor());
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
      .get(`${basePath}/auth/someUserId/sessions`)
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
      .get(`${basePath}/auth/${reg.id}/sessions`)
      .set('Authorization', `Bearer ${reg.accessToken}`)
      .expect(403);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(403);
  });

  it('200: ADMIN token can read sessions of target user -> returns array of RefreshTokenSessionDto', async () => {
    const password = 'strongPassword123';

    const targetEmail = `target_${Date.now()}@e2e.local`;
    const targetRegRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email: targetEmail, password })
      .expect(201);
    const targetUnknown: unknown = targetRegRes.body;
    expectRegisterResponseShape(targetUnknown);
    const target = targetUnknown;

    const adminEmail = `admin_${Date.now()}@e2e.local`;
    const adminRegRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email: adminEmail, password })
      .expect(201);
    const adminUnknown: unknown = adminRegRes.body;
    expectRegisterResponseShape(adminUnknown);
    const admin = adminUnknown;

    await prisma.user.update({
      where: { id: admin.id },
      data: { role: Role.ADMIN },
    });

    const adminLoginRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/login`)
      .send({ email: adminEmail, password })
      .expect(200);

    const adminToken = adminLoginRes.body as { accessToken: string };
    expect(typeof adminToken.accessToken).toBe('string');
    expect(adminToken.accessToken.length).toBeGreaterThan(10);

    const sessionsRes = await request(app.getHttpServer())
      .get(`${basePath}/auth/${target.id}/sessions`)
      .set('Authorization', `Bearer ${adminToken.accessToken}`)
      .expect(200);

    const sessionsUnknown: unknown = sessionsRes.body;
    expectSessionsArrayShape(sessionsUnknown);

    const sessions = sessionsUnknown;

    expect(sessions.length).toBeGreaterThanOrEqual(1);

    const targetActive = await prisma.refreshToken.findMany({
      where: { userId: target.id, revoked: false },
      orderBy: { createdAt: 'desc' },
    });
    expect(targetActive.length).toBeGreaterThanOrEqual(1);

    const latest = targetActive.at(0);
    expect(latest).toBeTruthy();

    const returnedJtis = new Set(sessions.map((s) => s.jti));
    expect(returnedJtis.has(latest!.jti)).toBe(true);
  });

  it('200: ADMIN запрос к несуществующему userId -> returns [] (current behavior)', async () => {
    const password = 'strongPassword123';

    const adminEmail = `admin2_${Date.now()}@e2e.local`;
    await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email: adminEmail, password })
      .expect(201);

    const admin = await prisma.user.findUnique({
      where: { email: adminEmail.toLowerCase() },
    });
    expect(admin).toBeTruthy();

    await prisma.user.update({
      where: { id: admin!.id },
      data: { role: Role.ADMIN },
    });

    const adminLoginRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/login`)
      .send({ email: adminEmail, password })
      .expect(200);

    const adminToken = adminLoginRes.body as { accessToken: string };

    const res = await request(app.getHttpServer())
      .get(`${basePath}/auth/not-existing-user-id/sessions`)
      .set('Authorization', `Bearer ${adminToken.accessToken}`)
      .expect(200);

    expect(Array.isArray(res.body)).toBe(true);
  });
});
