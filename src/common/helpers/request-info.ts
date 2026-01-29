import { Request } from 'express';
import { normalizeIp } from './ip-normalize';

const MAX_USER_AGENT_LENGTH = 255;

function normalizeUserAgent(ua: unknown): string {
  if (typeof ua === 'string') {
    const str = ua.trim();
    return str.length > MAX_USER_AGENT_LENGTH
      ? str.slice(0, MAX_USER_AGENT_LENGTH)
      : str;
  }

  if (Array.isArray(ua)) {
    return normalizeUserAgent(ua[0]);
  }

  return '';
}

export function extractRequestInfo(req: Request): {
  ip: string;
  userAgent: string;
} {
  const rawIp = req.ip || (Array.isArray(req.ips) ? req.ips[0] : '') || '';
  const ip = normalizeIp(rawIp);

  const userAgent = normalizeUserAgent(req.headers['user-agent']);

  return { ip, userAgent };
}
