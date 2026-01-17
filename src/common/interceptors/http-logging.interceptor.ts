import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { finalize } from 'rxjs/operators';
import type { Request, Response } from 'express';
import { AppLogger } from 'src/logger/logger.service';
import { extractRequestInfo } from 'src/common/helpers/request-info';
import { getRequestId } from 'src/common/request-context/request-context';
import { maskIp } from 'src/common/helpers/log-sanitize';

@Injectable()
export class HttpLoggingInterceptor implements NestInterceptor {
  constructor(private readonly logger: AppLogger) {
    this.logger.setContext(HttpLoggingInterceptor.name);
  }

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const http = context.switchToHttp();
    const req = http.getRequest<Request>();
    const res = http.getResponse<Response>();

    const start = Date.now();
    const { ip, userAgent } = extractRequestInfo(req);

    const path = req.path;
    const method = req.method;

    return next.handle().pipe(
      finalize(() => {
        const durationMs = Date.now() - start;
        const requestId = getRequestId();

        const user = req.user;

        const status = res.statusCode;

        this.logger.log(
          `${method} ${path} -> ${status} (${durationMs}ms)`,
          HttpLoggingInterceptor.name,
          {
            event: 'http.request',
            requestId,
            method,
            path,
            status,
            durationMs,
            userId: user?.userId,
            role: user?.role,
            sid: user?.sid,
            ipMasked: maskIp(ip),
            userAgent,
          },
        );
      }),
    );
  }
}
