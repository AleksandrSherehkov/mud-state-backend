import { Injectable } from '@nestjs/common';
import type { Request } from 'express';

import { normalizeIp } from 'src/common/net/ip-normalize';
import {
  TrustedProxyGeoService,
  type TrustedProxyGeo,
} from 'src/common/security/policy/trusted-proxy-geo.service';

const MAX_USER_AGENT_LENGTH = 255;

export type RequestGeo = TrustedProxyGeo;

export type RequestChallenge = {
  nonce?: string;
  solution?: string;
};

function normalizeUserAgent(ua: unknown): string {
  if (typeof ua === 'string') {
    const str = ua.trim();
    return str.length > MAX_USER_AGENT_LENGTH
      ? str.slice(0, MAX_USER_AGENT_LENGTH)
      : str;
  }
  if (Array.isArray(ua)) return normalizeUserAgent(ua[0]);
  return '';
}

function pickHeader(req: Request, name: string): string | undefined {
  const v = req.headers[name.toLowerCase()];
  if (typeof v === 'string') return v.trim() || undefined;
  if (Array.isArray(v)) return (v[0] ?? '').trim() || undefined;
  return undefined;
}

function extractChallengeFromHeaders(
  req: Request,
): RequestChallenge | undefined {
  const nonce = pickHeader(req, 'x-auth-challenge-nonce');
  const solution = pickHeader(req, 'x-auth-challenge-solution');

  if (!nonce && !solution) return undefined;

  return { nonce, solution };
}

@Injectable()
export class RequestInfoService {
  constructor(private readonly trustedProxyGeo: TrustedProxyGeoService) {}

  extract(req: Request): {
    ip: string;
    userAgent: string;
    geo?: RequestGeo;
    challenge?: RequestChallenge;
  } {
    const rawIp = req.ip || (Array.isArray(req.ips) ? req.ips[0] : '') || '';
    const ip = normalizeIp(rawIp);

    const userAgent = normalizeUserAgent(req.headers['user-agent']);
    const geo = this.trustedProxyGeo.extractTrustedGeo(req);
    const challenge = extractChallengeFromHeaders(req);

    return { ip, userAgent, geo, challenge };
  }
}
