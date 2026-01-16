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
import * as bcrypt from 'bcrypt';
import { Role } from '@prisma/client';

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

describe('Users E2E — PATCH /users/:id', () => {
  let app: INestApplication;
  let prisma: PrismaService;

  const API_PREFIX = process.env.API_PREFIX ?? 'api';
  const API_VERSION = process.env.API_VERSION ?? '1';
  const basePath = `/${API_PREFIX}/v${API_VERSION}`;

  async function seedUser(
    email: string,
    password: string,
    role: Role = Role.USER,
  ) {
    const hash = await bcrypt.hash(password, 10);
    return prisma.user.create({
      data: {
        email: email.trim().toLowerCase(),
        password: hash,
        role: role,
      },
      select: { id: true, email: true, role: true },
    });
  }

  async function login(email: string, password: string) {
    const res = await request(app.getHttpServer())
      .post(`${basePath}/auth/login`)
      .send({ email, password })
      .expect(200);

    const body = res.body as { accessToken: string };
    expect(typeof body.accessToken).toBe('string');
    expect(body.accessToken.length).toBeGreaterThan(10);
    return body.accessToken;
  }

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
      .patch(`${basePath}/users/some-id`)
      .send({ email: 'x@e2e.local' })
      .expect(401);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(401);
  });

  it('403: USER token -> Forbidden (ADMIN only)', async () => {
    const password = 'strongPassword123';
    const user = await seedUser(
      `user_${Date.now()}@e2e.local`,
      password,
      'USER',
    );

    const accessToken = await login(user.email, password);

    const res = await request(app.getHttpServer())
      .patch(`${basePath}/users/${user.id}`)
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ email: `hacker_${Date.now()}@e2e.local` })
      .expect(403);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(403);
  });

  it('404: ADMIN token -> user not found', async () => {
    const password = 'strongPassword123';
    const admin = await seedUser(
      `admin_${Date.now()}@e2e.local`,
      password,
      'ADMIN',
    );
    const adminToken = await login(admin.email, password);

    const res = await request(app.getHttpServer())
      .patch(`${basePath}/users/cl_not_exists_123`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ email: `new_${Date.now()}@e2e.local` })
      .expect(404);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(404);
  });

  it('200: ADMIN -> can update email (lowercase) and returns PublicUserDto', async () => {
    const password = 'strongPassword123';

    const admin = await seedUser(
      `admin_${Date.now()}@e2e.local`,
      password,
      'ADMIN',
    );
    const target = await seedUser(
      `target_${Date.now()}@e2e.local`,
      password,
      'USER',
    );

    const adminToken = await login(admin.email, password);

    const newEmailRaw = `NEW_${Date.now()}@E2E.LOCAL`;

    const res = await request(app.getHttpServer())
      .patch(`${basePath}/users/${target.id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ email: newEmailRaw })
      .expect(200);

    const bodyUnknown: unknown = res.body;
    expectPublicUserShape(bodyUnknown);
    const body: PublicUserResponse = bodyUnknown;

    expect(body.id).toBe(target.id);
    expect(body.email).toBe(newEmailRaw.toLowerCase());

    const db = await prisma.user.findUnique({
      where: { id: target.id },
      select: { email: true },
    });
    expect(db?.email).toBe(newEmailRaw.toLowerCase());
  });

  it('200: ADMIN -> can update role', async () => {
    const password = 'strongPassword123';

    const admin = await seedUser(
      `admin_${Date.now()}@e2e.local`,
      password,
      'ADMIN',
    );
    const target = await seedUser(
      `target_${Date.now()}@e2e.local`,
      password,
      'USER',
    );

    const adminToken = await login(admin.email, password);

    const res = await request(app.getHttpServer())
      .patch(`${basePath}/users/${target.id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ role: Role.MODERATOR })
      .expect(200);

    const bodyUnknown: unknown = res.body;
    expectPublicUserShape(bodyUnknown);
    const body: PublicUserResponse = bodyUnknown;

    expect(body.id).toBe(target.id);
    expect(body.role).toBe(Role.MODERATOR);

    const db = await prisma.user.findUnique({
      where: { id: target.id },
      select: { role: true },
    });
    expect(db?.role).toBe('MODERATOR');
  });

  it('409: ADMIN -> cannot set email that already exists', async () => {
    const password = 'strongPassword123';

    const admin = await seedUser(
      `admin_${Date.now()}@e2e.local`,
      password,
      'ADMIN',
    );
    const a = await seedUser(`a_${Date.now()}@e2e.local`, password, 'USER');
    const b = await seedUser(`b_${Date.now()}@e2e.local`, password, 'USER');

    const adminToken = await login(admin.email, password);

    const res = await request(app.getHttpServer())
      .patch(`${basePath}/users/${b.id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ email: a.email })
      .expect(409);

    const body = res.body as HttpErrorResponse;
    expect(body.statusCode).toBe(409);
  });

  it('400: ADMIN -> rejects unknown fields (forbidNonWhitelisted)', async () => {
    const password = 'strongPassword123';

    const admin = await seedUser(
      `admin_${Date.now()}@e2e.local`,
      password,
      'ADMIN',
    );
    const target = await seedUser(
      `target_${Date.now()}@e2e.local`,
      password,
      'USER',
    );

    const adminToken = await login(admin.email, password);

    await request(app.getHttpServer())
      .patch(`${basePath}/users/${target.id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ lol: 'nope' })
      .expect(400);
  });
});
