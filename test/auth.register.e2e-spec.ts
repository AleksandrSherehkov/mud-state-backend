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

type RegisterResponse = {
  id: string;
  email: string;
  role: Role;
  createdAt: string;
  accessToken: string;
  refreshToken: string;
  jti: string;
};

type TokenResponse = {
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

type LogoutResponse = {
  loggedOut: boolean;
  terminatedAt: string | null;
};

type HttpErrorResponse = {
  statusCode: number;
  message: string | string[];
  error: string;
};

function envBool(v: unknown, def = false): boolean {
  if (typeof v !== 'string') return def;
  const s = v.trim().toLowerCase();
  if (s === 'true') return true;
  if (s === 'false') return false;
  return def;
}

function envInt(v: unknown, def: number): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : def;
}

function buildValidPassword(): string {
  const min = envInt(process.env.PASSWORD_MIN_LENGTH, 8);
  const max = envInt(process.env.PASSWORD_MAX_LENGTH, 72);

  const requireUpper = envBool(process.env.PASSWORD_REQUIRE_UPPERCASE, true);
  const requireDigit = envBool(process.env.PASSWORD_REQUIRE_DIGIT, true);
  const requireSpecial = envBool(process.env.PASSWORD_REQUIRE_SPECIAL, false);

  let pwd = 'a';

  if (requireUpper) pwd += 'A';
  if (requireDigit) pwd += '1';
  if (requireSpecial) pwd += '!';

  while (pwd.length < min) pwd += 'x';

  if (pwd.length > max) pwd = pwd.slice(0, max);

  return pwd;
}

describe('Auth E2E — full flow', () => {
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

  it('register → me → refresh → me → logout → refresh(401)', async () => {
    const email = `flow_${Date.now()}@e2e.local`;
    const password = buildValidPassword();

    const registerRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email, password })
      .expect(201);

    const reg = registerRes.body as RegisterResponse;

    expect(typeof reg.id).toBe('string');
    expect(reg.id.length).toBeGreaterThan(0);

    expect(reg.email).toBe(email.toLowerCase());
    expect(reg.role).toBe('USER');

    expect(typeof reg.createdAt).toBe('string');
    expect(Number.isNaN(Date.parse(reg.createdAt))).toBe(false);

    expect(typeof reg.accessToken).toBe('string');
    expect(reg.accessToken.length).toBeGreaterThan(20);

    expect(typeof reg.refreshToken).toBe('string');
    expect(reg.refreshToken.length).toBeGreaterThan(20);

    expect(typeof reg.jti).toBe('string');
    expect(reg.jti.length).toBeGreaterThan(10);

    const userId = reg.id;
    const accessToken1 = reg.accessToken;
    const refreshToken1 = reg.refreshToken;
    const jti1 = reg.jti;

    const me1Res = await request(app.getHttpServer())
      .get(`${basePath}/auth/me`)
      .set('Authorization', `Bearer ${accessToken1}`)
      .expect(200);

    const me1 = me1Res.body as MeResponse;

    expect(me1.id).toBe(userId);
    expect(me1.email).toBe(email.toLowerCase());
    expect(me1.role).toBe('USER');
    expect(Number.isNaN(Date.parse(me1.createdAt))).toBe(false);

    const refreshRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/refresh`)
      .send({ refreshToken: refreshToken1 })
      .expect(200);

    const tokens2 = refreshRes.body as TokenResponse;

    expect(typeof tokens2.accessToken).toBe('string');
    expect(tokens2.accessToken.length).toBeGreaterThan(20);

    expect(typeof tokens2.refreshToken).toBe('string');
    expect(tokens2.refreshToken.length).toBeGreaterThan(20);

    expect(typeof tokens2.jti).toBe('string');
    expect(tokens2.jti.length).toBeGreaterThan(10);

    expect(tokens2.refreshToken).not.toBe(refreshToken1);
    expect(tokens2.jti).not.toBe(jti1);

    const accessToken2 = tokens2.accessToken;
    const refreshToken2 = tokens2.refreshToken;

    const me2Res = await request(app.getHttpServer())
      .get(`${basePath}/auth/me`)
      .set('Authorization', `Bearer ${accessToken2}`)
      .expect(200);

    const me2 = me2Res.body as MeResponse;
    expect(me2.id).toBe(userId);

    const logoutRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/logout`)
      .set('Authorization', `Bearer ${accessToken2}`)
      .expect(200);

    const logoutBody = logoutRes.body as LogoutResponse;

    expect(logoutBody.loggedOut).toBe(true);
    expect(
      logoutBody.terminatedAt === null ||
        typeof logoutBody.terminatedAt === 'string',
    ).toBe(true);

    const refreshAfterLogoutRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/refresh`)
      .send({ refreshToken: refreshToken2 })
      .expect(401);

    const err = refreshAfterLogoutRes.body as HttpErrorResponse;
    expect(err.statusCode).toBe(401);
    expect(err.error).toBe('Unauthorized');
  });
});
