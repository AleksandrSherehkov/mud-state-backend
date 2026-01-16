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

type MeResponse = {
  id: string;
  email: string;
  role: Role;
  createdAt: string;
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
}

function expectMeResponseShape(value: unknown): asserts value is MeResponse {
  expect(value).toBeTruthy();
  expect(typeof value).toBe('object');

  const v = value as Record<string, unknown>;

  for (const k of ['id', 'email', 'role', 'createdAt'] as const) {
    expect(k in v).toBe(true);
    expect(typeof v[k]).toBe('string');
    expect((v[k] as string).length).toBeGreaterThan(0);
  }

  expect(Number.isNaN(Date.parse(v.createdAt as string))).toBe(false);
}

describe('Auth E2E — me', () => {
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

  it('401: /me without token -> Unauthorized', async () => {
    const res = await request(app.getHttpServer())
      .get(`${basePath}/auth/me`)
      .expect(401);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(401);
    expect(
      typeof body.message === 'string' || Array.isArray(body.message),
    ).toBe(true);
  });

  it('200: /me with valid accessToken -> returns id/email/role/createdAt', async () => {
    const email = `me_${Date.now()}@e2e.local`;
    const password = 'strongPassword123';

    const regRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email, password })
      .expect(201);

    const regUnknown: unknown = regRes.body;
    expectRegisterResponseShape(regUnknown);
    const reg: RegisterResponse = regUnknown;

    const meRes = await request(app.getHttpServer())
      .get(`${basePath}/auth/me`)
      .set('Authorization', `Bearer ${reg.accessToken}`)
      .expect(200);

    const meUnknown: unknown = meRes.body;
    expectMeResponseShape(meUnknown);
    const me: MeResponse = meUnknown;

    expect(me.id).toBe(reg.id);
    expect(me.email).toBe(reg.email);
    expect(me.role).toBe(reg.role);
  });

  it('401: /me with malformed token -> Unauthorized', async () => {
    const res = await request(app.getHttpServer())
      .get(`${basePath}/auth/me`)
      .set('Authorization', `Bearer not-a-jwt`)
      .expect(401);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(401);
  });

  it('401: /me with jwt-shaped but invalid signature -> Unauthorized', async () => {
    const fakeJwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4IiwiZW1haWwiOiJ4QHguY29tIiwicm9sZSI6IlVTRVIiLCJzaWQiOiJ4IiwianRpIjoieCIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjo0MTAyNDQ0ODAwfQ.invalidsignature';

    const res = await request(app.getHttpServer())
      .get(`${basePath}/auth/me`)
      .set('Authorization', `Bearer ${fakeJwt}`)
      .expect(401);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(401);
  });
});
