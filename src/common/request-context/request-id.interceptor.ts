import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { randomUUID } from 'node:crypto';
import { Observable } from 'rxjs';
import { requestContext } from './request-context';

function getHeader(req: Request, name: string): string | undefined {
  const v = req.get(name);
  return typeof v === 'string' && v.trim() ? v.trim() : undefined;
}

@Injectable()
export class RequestIdInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const http = context.switchToHttp();

    const req = http.getRequest<Request>();
    const res = http.getResponse<Response>();

    const incoming =
      getHeader(req, 'x-request-id') ?? getHeader(req, 'x-correlation-id');

    const requestId = incoming ?? randomUUID();

    res.setHeader('x-request-id', requestId);

    return requestContext.run({ requestId }, () => next.handle());
  }
}
