# MUD State Backend

This project provides the API and database layer for a Multi User Dungeon (MUD) simulation. It is built with [NestJS](https://nestjs.com) and [Prisma](https://www.prisma.io/) to manage players, sessions and other game data.

## Requirements

- Node.js **20 or higher** (tested with Node.js 22)
- PostgreSQL instance available via `DATABASE_URL`

## Setup

1. Install dependencies:

   ```bash
   npm install
   ```
   > **Note**: Prisma requires internet access during installation to download
   > its engine binaries. For offline environments, prebuild or cache the
   > Prisma engines.

2. Copy `.env.example` to `.env` and adjust the values as needed:

   ```bash
   cp .env.example .env
   ```

  The example file lists all environment variables consumed by the
  `ConfigService` such as `DATABASE_URL`, `JWT_ACCESS_SECRET`,
  `JWT_REFRESH_SECRET`, `PORT`, `BASE_URL`, `JWT_ACCESS_EXPIRES_IN`,
  `JWT_REFRESH_EXPIRES_IN`, and `BCRYPT_SALT_ROUNDS`.
  It now also includes throttling options `THROTTLE_TTL` and
  `THROTTLE_LIMIT` which control the request rate limit window (in
  seconds) and the maximum number of requests allowed within that
  window.  The cleanup schedule can be adjusted via the new
  `TOKEN_CLEANUP_DAYS` setting which defines how old revoked tokens
  must be before removal.

  Logging can be tuned with `LOG_DIR` (log directory), `LOG_MAX_SIZE` (rotate size), and `LOG_MAX_FILES` (retention period).

3. Generate the Prisma client and apply database migrations:

   ```bash
   npx prisma generate
   npx prisma migrate deploy
   ```

## Running locally

Start the API in watch mode:

```bash
npm run start:dev
```

Swagger documentation will be available at `${BASE_URL}/api/docs` once the server starts.

## Throttling

The API enforces a global request rate limit controlled by `THROTTLE_TTL` and
`THROTTLE_LIMIT`. Endpoints that require authentication are exempt from this
limit. The following routes skip throttling:

- `POST /auth/logout`
- `GET /auth/me`
- `GET /auth/:userId/sessions`
- `GET /auth/sessions/active`
- `POST /auth/sessions/terminate-others`
- `GET /auth/sessions/me`
- `POST /auth/sessions/terminate`
- All routes under `/users/*`

## License

This project is released under the MIT License.
