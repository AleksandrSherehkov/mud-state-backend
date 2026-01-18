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

type PublicUserResponse = {
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
  expect(Number.isNaN(Date.parse(v.createdAt as string))).toBe(false);
}

function expectPublicUserShape(
  value: unknown,
): asserts value is PublicUserResponse {
  expect(value).toBeTruthy();
  expect(typeof value).toBe('object');

  const v = value as Record<string, unknown>;
  for (const k of ['id', 'email', 'role', 'createdAt'] as const) {
    expect(k in v).toBe(true);
  }

  expect(typeof v.id).toBe('string');
  expect(typeof v.email).toBe('string');
  expect(typeof v.role).toBe('string');
  expect(typeof v.createdAt).toBe('string');

  expect((v.id as string).length).toBeGreaterThan(0);
  expect(Number.isNaN(Date.parse(v.createdAt as string))).toBe(false);

  expect('password' in v).toBe(false);
}

describe('Users E2E — GET /users/by-email?email=...', () => {
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
      .get(`${basePath}/users/by-email`)
      .query({ email: 'user@e2e.local' })
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
      .get(`${basePath}/users/by-email`)
      .query({ email })
      .set('Authorization', `Bearer ${reg.accessToken}`)
      .expect(403);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(403);
  });

  it('404: ADMIN token -> Not Found when email does not exist', async () => {
    const email = `admin_nf_${Date.now()}@e2e.local`;
    const password = 'strongPassword123';

    const regRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email, password })
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
      .send({ email, password })
      .expect(200);

    const token = loginRes.body as { accessToken: string };
    expect(typeof token.accessToken).toBe('string');

    const res = await request(app.getHttpServer())
      .get(`${basePath}/users/by-email`)
      .query({ email: 'missing@e2e.local' })
      .set('Authorization', `Bearer ${token.accessToken}`)
      .expect(404);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(404);
  });

  it('200: ADMIN token -> returns PublicUserDto by email (normalizes trim/lowercase)', async () => {
    const password = 'strongPassword123';

    const adminEmail = `admin_${Date.now()}@e2e.local`;
    const adminRegRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email: adminEmail, password })
      .expect(201);

    const adminRegUnknown: unknown = adminRegRes.body;
    expectRegisterResponseShape(adminRegUnknown);
    const adminReg: RegisterResponse = adminRegUnknown;

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

    const rawEmail = `TaRgEt_${Date.now()}@e2e.local`;
    const userRegRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email: rawEmail, password })
      .expect(201);

    const userRegUnknown: unknown = userRegRes.body;
    expectRegisterResponseShape(userRegUnknown);
    const target: RegisterResponse = userRegUnknown;

    const queryEmail = `  ${rawEmail.toUpperCase()}  `;
    const res = await request(app.getHttpServer())
      .get(`${basePath}/users/by-email`)
      .query({ email: queryEmail })
      .set('Authorization', `Bearer ${adminToken.accessToken}`)
      .expect(200);

    const bodyUnknown: unknown = res.body;
    expectPublicUserShape(bodyUnknown);
    const body: PublicUserResponse = bodyUnknown;

    expect(body.id).toBe(target.id);
    expect(body.email).toBe(rawEmail.toLowerCase());
  });
});
