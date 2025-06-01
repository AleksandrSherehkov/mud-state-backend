import { Request } from 'express';

export function extractRequestInfo(req: Request): {
  ip: string;
  userAgent: string;
} {
  const forwarded = req.headers['x-forwarded-for'];
  const ip: string =
    (Array.isArray(forwarded)
      ? forwarded[0]
      : forwarded?.toString().split(',')[0].trim()) ||
    req.ip ||
    '';
  const userAgent = req.headers['user-agent'] || '';
  return { ip, userAgent };
}
