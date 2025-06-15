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

2. Create a `.env` file and define the required environment variables:

   ```text
   DATABASE_URL=postgres://user:password@localhost:5432/dbname
   JWT_ACCESS_SECRET=accessSecret
   JWT_REFRESH_SECRET=refreshSecret
   # Optional overrides
   PORT=3000
   BASE_URL=http://localhost:3000
   JWT_ACCESS_EXPIRES_IN=15m
   JWT_REFRESH_EXPIRES_IN=7d
   BCRYPT_SALT_ROUNDS=10
   ```

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
