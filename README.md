# MUD State Backend

This project provides the API and database layer for a Multi User Dungeon (MUD) simulation. It is built with [NestJS](https://nestjs.com) and [Prisma](https://www.prisma.io/) to manage players, sessions and other game data.

## Requirements

- Node.js **20.x**
- PostgreSQL instance available via `DATABASE_URL`

## Setup

1. Install dependencies:

   ```bash
   npm install
   ```

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
  window.

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

## License

This project is released under the MIT License.
