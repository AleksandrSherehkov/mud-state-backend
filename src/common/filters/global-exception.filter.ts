import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { AppLogger } from 'src/logger/logger.service';
import { extractRequestInfo } from 'src/common/helpers/request-info';
import { getRequestId } from 'src/common/request-context/request-context';
import { maskIp } from 'src/common/helpers/log-sanitize';

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

    const user = req.user;

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

    if (exception instanceof HttpException) {
      const body = exception.getResponse();
      return res.status(status).json(body);
    }

    return res.status(status).json({
      statusCode: status,
      message: status >= 500 ? 'Internal server error' : 'Error',
    });
  }
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
