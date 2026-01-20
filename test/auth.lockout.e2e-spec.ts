import {
  INestApplication,
  ValidationPipe,
  VersioningType,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as request from 'supertest';
import { useContainer } from 'class-validator';

import { PrismaService } from 'src/prisma/prisma.service';
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

type TokenResponse = {
  accessToken: string;
  refreshToken: string;
  jti: string;
};

type HttpErrorResponse = {
  statusCode: number;
  message: string | string[];
  error?: string;
};

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

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

// пароль под текущую policy из ENV
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

describe('Auth E2E — lockout / progressive delay', () => {
  let app: INestApplication;
  let prisma: PrismaService;

  const API_PREFIX = process.env.API_PREFIX ?? 'api';
  const API_VERSION = process.env.API_VERSION ?? '1';
  const basePath = `/${API_PREFIX}/v${API_VERSION}`;

  beforeAll(async () => {
    // --- make test deterministic & avoid 429 (throttle) ---
    process.env.NODE_ENV = 'test';
    process.env.APP_ENV = 'test';

    // Keep throttler from interfering with login attempts
    process.env.THROTTLE_TTL = '60';
    process.env.THROTTLE_LIMIT = '100';

    // Lock policy (fast for tests)
    process.env.AUTH_LOCK_MAX_ATTEMPTS = '3';
    process.env.AUTH_LOCK_BASE_SECONDS = '1'; // attempt 3 => delay 4s
    process.env.AUTH_LOCK_MAX_SECONDS = '60';
    process.env.AUTH_LOCK_WINDOW_SECONDS = '900';

    // Password policy for tests (so buildValidPassword() is stable)
    process.env.PASSWORD_MIN_LENGTH = process.env.PASSWORD_MIN_LENGTH ?? '8';
    process.env.PASSWORD_MAX_LENGTH = process.env.PASSWORD_MAX_LENGTH ?? '72';
    process.env.PASSWORD_REQUIRE_UPPERCASE =
      process.env.PASSWORD_REQUIRE_UPPERCASE ?? 'true';
    process.env.PASSWORD_REQUIRE_DIGIT =
      process.env.PASSWORD_REQUIRE_DIGIT ?? 'true';
    process.env.PASSWORD_REQUIRE_SPECIAL =
      process.env.PASSWORD_REQUIRE_SPECIAL ?? 'false';

    // IMPORTANT: dynamic import AFTER env setup
    const { AppModule } = await import('src/app.module');

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

    // ВАЖНО: DI для class-validator constraints (PasswordPolicyValidator)
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

  it('locks after N wrong passwords, blocks correct password until lock expires, then allows login', async () => {
    const email = `lock_${Date.now()}@e2e.local`;
    const password = buildValidPassword();

    // register
    const registerRes = await request(app.getHttpServer())
      .post(`${basePath}/auth/register`)
      .send({ email, password })
      .expect(201);

    const reg = registerRes.body as RegisterResponse;
    const userId = reg.id;

    expect(reg.email).toBe(email.toLowerCase());
    expect(typeof userId).toBe('string');
    expect(userId.length).toBeGreaterThan(0);

    // 3 wrong attempts -> each 401
    for (let i = 0; i < 3; i++) {
      const res = await request(app.getHttpServer())
        .post(`${basePath}/auth/login`)
        .send({ email, password: 'wrongPassword123' })
        .expect(401);

      const body = res.body as HttpErrorResponse;
      expect(body.statusCode).toBe(401);
    }

    // now even correct password should be blocked (locked)
    const blocked = await request(app.getHttpServer())
      .post(`${basePath}/auth/login`)
      .send({ email, password })
      .expect(401);

    const blockedBody = blocked.body as HttpErrorResponse;
    expect(blockedBody.statusCode).toBe(401);

    // wait for lock to expire:
    // maxAttempts=3, baseSec=1 => delay = 1 * 2^(3-1) = 4s
    await sleep(4200);

    // after expiry correct login should succeed
    const ok = await request(app.getHttpServer())
      .post(`${basePath}/auth/login`)
      .send({ email, password })
      .expect(200);

    const tokens = ok.body as TokenResponse;
    expect(typeof tokens.accessToken).toBe('string');
    expect(tokens.accessToken.length).toBeGreaterThan(20);
    expect(typeof tokens.refreshToken).toBe('string');
    expect(tokens.refreshToken.length).toBeGreaterThan(20);
    expect(typeof tokens.jti).toBe('string');
    expect(tokens.jti.length).toBeGreaterThan(10);

    // optional sanity: user still exists
    const user = await prisma.user.findUnique({ where: { id: userId } });
    expect(user).toBeTruthy();
  });
});
