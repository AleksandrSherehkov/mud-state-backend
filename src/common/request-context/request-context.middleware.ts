import { randomUUID } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import { requestContext } from './request-context';

function getHeader(req: Request, name: string): string | undefined {
  const v = req.get(name);
  return typeof v === 'string' && v.trim() ? v.trim() : undefined;
}

export function requestContextMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const incoming =
    getHeader(req, 'x-request-id') ?? getHeader(req, 'x-correlation-id');

  const requestId = incoming ?? randomUUID();

  res.setHeader('x-request-id', requestId);

  requestContext.run({ requestId }, () => next());
}
