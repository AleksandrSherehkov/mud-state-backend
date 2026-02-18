import type { NestExpressApplication } from '@nestjs/platform-express';
import { ConfigService } from '@nestjs/config';
import helmet from 'helmet';
import * as cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';

import { parseList } from './parse-list';

export function applyHelmet(
  app: NestExpressApplication,
  config: ConfigService,
  opts: { shouldEnableSwagger: boolean; isProd: boolean },
) {
  const { shouldEnableSwagger, isProd } = opts;

  app.use(
    helmet({
      contentSecurityPolicy: shouldEnableSwagger
        ? false
        : {
            useDefaults: true,
            directives: {
              defaultSrc: ["'none'"],
              baseUri: ["'none'"],
              frameAncestors: ["'none'"],
              formAction: ["'none'"],
            },
          },

      crossOriginResourcePolicy: shouldEnableSwagger
        ? false
        : { policy: 'same-site' },

      hsts: isProd
        ? { maxAge: 15552000, includeSubDomains: true, preload: true }
        : false,

      referrerPolicy: { policy: 'no-referrer' },
    }),
  );
}

export function applyCookieParser(
  app: NestExpressApplication,
  config: ConfigService,
) {
  const cookieSecret = config.get<string>('COOKIE_SECRET');
  if (!cookieSecret) throw new Error('COOKIE_SECRET is not set');
  app.use(cookieParser(cookieSecret));
}

export function applyCors(
  app: NestExpressApplication,
  config: ConfigService,
  opts: { isProd: boolean },
) {
  const { isProd } = opts;

  const origins = parseList(config.get<string>('CORS_ORIGINS'));

  const corsAllowNoOrigin =
    String(config.get('CORS_ALLOW_NO_ORIGIN') ?? '')
      .toLowerCase()
      .trim() === 'true';

  const allowAnyInNonProd = !isProd && origins.length === 0;

  app.enableCors({
    origin: (origin, cb) => {
      if (!origin) {
        if (isProd && !corsAllowNoOrigin) {
          return cb(new Error('CORS blocked: missing Origin'), false);
        }
        return cb(null, true);
      }

      if (allowAnyInNonProd) return cb(null, true);

      if (origins.includes(origin)) return cb(null, true);
      return cb(new Error(`CORS blocked for origin: ${origin}`), false);
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Authorization',
      'Content-Type',
      'Accept',
      'X-CSRF-Token',
      'X-CSRF-M2M-Kid',
      'X-CSRF-M2M-TS',
      'X-CSRF-M2M-Nonce',
      'X-CSRF-M2M-Sign',
    ],
    credentials: true,
    maxAge: 600,
  });
}

export function applyValidation(app: NestExpressApplication) {
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );
}
