import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import type { Request, Response } from 'express-serve-static-core';
import { ConfigService } from '@nestjs/config';
import { AppLogger } from 'src/logger/logger.service';
import { extractRequestInfo } from 'src/common/helpers/request-info';
import { getRequestId } from 'src/common/request-context/request-context';
import {
  maskIp,
  hashId,
  normalizeUserAgent,
} from 'src/common/helpers/log-sanitize';
import { UserFromJwt } from 'src/common/types/user-from-jwt';

type ErrorBody = {
  statusCode: number;
  message: string | string[];
  error: string;
  timestamp: string;
  path: string;
  requestId?: string;
};

function isUserFromJwt(v: unknown): v is UserFromJwt {
  if (!v || typeof v !== 'object') return false;

  const u = v as Partial<UserFromJwt>;

  return (
    typeof u.userId === 'string' &&
    typeof u.email === 'string' &&
    typeof u.sid === 'string' &&
    typeof u.role === 'string'
  );
}

@Catch()
@Injectable()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly isProd: boolean;

  constructor(
    private readonly logger: AppLogger,
    private readonly config: ConfigService,
  ) {
    this.logger.setContext(GlobalExceptionFilter.name);

    const env = (
      this.config.get<string>('APP_ENV', 'development') || 'development'
    ).toLowerCase();

    this.isProd = env === 'production';
  }

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const req = ctx.getRequest<Request>();
    const res = ctx.getResponse<Response>();

    const { ip, userAgent, geo } = extractRequestInfo(req);

    const rawUser: unknown = (req as Request & { user?: unknown }).user;
    const user = isUserFromJwt(rawUser) ? rawUser : undefined;

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const exceptionName =
      exception instanceof Error ? exception.name : 'UnknownException';

    const requestId = getRequestId();

    const ua = normalizeUserAgent(userAgent);

    const meta = {
      event: 'http.exception',
      requestId,
      method: req.method,
      path: req.path,
      status,
      userId: user?.userId,
      role: user?.role,
      sid: user?.sid,
      ipMasked: maskIp(ip),
      uaHash: ua ? hashId(ua) : undefined,
      geoCountry: geo?.country,
      geoAsn: geo?.asn,
      asOrgHash: geo?.asOrgHash,
    };

    const details =
      exception instanceof HttpException
        ? safeHttpExceptionMessage(exception)
        : exception instanceof Error
          ? exception.message
          : String(exception);

    const logMessage = this.isProd
      ? `${req.method} ${req.path} -> ${status} ${exceptionName}`
      : `${req.method} ${req.path} -> ${status} ${exceptionName}: ${details}`;

    if (status >= 500) {
      const trace =
        !this.isProd && exception instanceof Error
          ? exception.stack
          : undefined;
      this.logger.error(logMessage, trace, GlobalExceptionFilter.name, meta);
    } else {
      this.logger.warn(logMessage, GlobalExceptionFilter.name, meta);
    }

    const body = normalizeErrorBody(exception, status, req.path, requestId);
    return res.status(status).json(body);
  }
}

function normalizeErrorBody(
  exception: unknown,
  status: number,
  path: string,
  requestId?: string,
): ErrorBody {
  const timestamp = new Date().toISOString();

  if (exception instanceof HttpException) {
    return normalizeHttpExceptionBody(
      exception,
      status,
      path,
      timestamp,
      requestId,
    );
  }

  return normalizeNonHttpExceptionBody(status, path, timestamp, requestId);
}

function normalizeHttpExceptionBody(
  ex: HttpException,
  status: number,
  path: string,
  timestamp: string,
  requestId?: string,
): ErrorBody {
  const r = ex.getResponse();

  if (r && typeof r === 'object') {
    return normalizeHttpExceptionObjectResponse(
      ex,
      r as Record<string, unknown>,
      status,
      path,
      timestamp,
      requestId,
    );
  }

  const msg = typeof r === 'string' ? r : ex.message;

  return {
    statusCode: status,
    message: msg,
    error: HttpStatus[status] ?? 'Error',
    timestamp,
    path,
    requestId,
  };
}

function normalizeHttpExceptionObjectResponse(
  ex: HttpException,
  o: Record<string, unknown>,
  status: number,
  path: string,
  timestamp: string,
  requestId?: string,
): ErrorBody {
  const message = pickMessageFromHttpExceptionResponse(o, ex);
  const error = pickErrorFromHttpExceptionResponse(o, status);

  return {
    statusCode: status,
    message,
    error,
    timestamp,
    path,
    requestId,
  };
}

function pickMessageFromHttpExceptionResponse(
  o: Record<string, unknown>,
  ex: HttpException,
): string | string[] {
  const raw = o.message;

  if (Array.isArray(raw)) {
    const arr = raw.filter((x): x is string => typeof x === 'string');
    return arr.length > 0 ? arr : ex.message;
  }

  if (typeof raw === 'string') return raw;

  return ex.message;
}

function pickErrorFromHttpExceptionResponse(
  o: Record<string, unknown>,
  status: number,
): string {
  if (typeof o.error === 'string') return o.error;

  if (typeof o.statusCode === 'number') {
    return HttpStatus[status] ?? 'Error';
  }

  return 'Error';
}

function normalizeNonHttpExceptionBody(
  status: number,
  path: string,
  timestamp: string,
  requestId?: string,
): ErrorBody {
  return {
    statusCode: status,
    message: status >= 500 ? 'Internal server error' : 'Error',
    error: HttpStatus[status] ?? 'Error',
    timestamp,
    path,
    requestId,
  };
}

function safeHttpExceptionMessage(ex: HttpException): string {
  const r: unknown = ex.getResponse();

  if (typeof r === 'string') return r;

  if (r && typeof r === 'object') {
    const msg = (r as Record<string, unknown>).message;

    if (typeof msg === 'string') return msg;
    if (Array.isArray(msg))
      return msg.filter((x) => typeof x === 'string').join('; ');
  }

  return ex.message;
}
