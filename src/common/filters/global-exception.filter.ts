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
import { maskIp } from 'src/common/helpers/log-sanitize';
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

    const { ip, userAgent } = extractRequestInfo(req);

    const rawUser: unknown = (req as Request & { user?: unknown }).user;
    const user = isUserFromJwt(rawUser) ? rawUser : undefined;

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const exceptionName =
      exception instanceof Error ? exception.name : 'UnknownException';

    const requestId = getRequestId();

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
      userAgent,
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
    const r = exception.getResponse();

    // Nest ValidationPipe обычно отдаёт { statusCode, message: string[], error }
    if (r && typeof r === 'object') {
      const o = r as Record<string, unknown>;

      const message = Array.isArray(o.message)
        ? o.message.filter((x) => typeof x === 'string')
        : typeof o.message === 'string'
          ? o.message
          : exception.message;

      const error =
        typeof o.error === 'string'
          ? o.error
          : typeof o.statusCode === 'number'
            ? (HttpStatus[status] ?? 'Error')
            : 'Error';

      return {
        statusCode: status,
        message,
        error,
        timestamp,
        path,
        requestId,
      };
    }

    // если getResponse() строка — приводим к нормальной форме
    const msg = typeof r === 'string' ? r : exception.message;

    return {
      statusCode: status,
      message: msg,
      error: HttpStatus[status] ?? 'Error',
      timestamp,
      path,
      requestId,
    };
  }

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
