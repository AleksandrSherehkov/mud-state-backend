import { Injectable } from '@nestjs/common';
import type { Request } from 'express';
import { createHash } from 'node:crypto';

import { normalizeIp } from 'src/common/net/ip-normalize';
import { SecurityPolicyService } from 'src/common/security/policy/security-policy.service';

const MAX_USER_AGENT_LENGTH = 255;

export type RequestGeo = {
  country?: string;
  asn?: number;
  asOrgHash?: string;
};

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

function normalizeCountry(v?: string): string | undefined {
  const s = (v ?? '').trim().toUpperCase();
  if (/^[A-Z]{2}$/.test(s)) return s;
  return undefined;
}

function normalizeAsn(v?: string): number | undefined {
  const s = (v ?? '').trim();
  const m = /^(?:AS)?(\d{1,10})$/.exec(s.toUpperCase());
  if (!m) return undefined;
  const n = Number(m[1]);
  if (!Number.isInteger(n) || n <= 0) return undefined;
  return n;
}

function normalizeAsOrg(v?: string): string | undefined {
  const s = (v ?? '').trim().replaceAll(/\s+/g, ' ');
  if (!s) return undefined;
  return s.length > 128 ? s.slice(0, 128) : s;
}

function hashOrg(v: string): string {
  return createHash('sha256').update(v).digest('hex');
}

function extractGeoFromHeaders(req: Request): RequestGeo | undefined {
  const cfCountry = pickHeader(req, 'cf-ipcountry');

  const xCountry =
    pickHeader(req, 'x-geo-country') ??
    pickHeader(req, 'x-country') ??
    pickHeader(req, 'x-forwarded-country');

  const xAsn = pickHeader(req, 'x-geo-asn') ?? pickHeader(req, 'x-asn');

  const xAsOrg =
    pickHeader(req, 'x-geo-asn-org') ?? pickHeader(req, 'x-asn-org');

  const country = normalizeCountry(cfCountry ?? xCountry);
  const asn = normalizeAsn(xAsn);

  const asOrgRaw = normalizeAsOrg(xAsOrg);
  const asOrgHash = asOrgRaw ? hashOrg(asOrgRaw) : undefined;

  if (!country && !asn && !asOrgHash) return undefined;
  return { country, asn, asOrgHash };
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
  constructor(private readonly policy: SecurityPolicyService) {}

  extract(req: Request): {
    ip: string;
    userAgent: string;
    geo?: RequestGeo;
    challenge?: RequestChallenge;
  } {
    const rawIp = req.ip || (Array.isArray(req.ips) ? req.ips[0] : '') || '';
    const ip = normalizeIp(rawIp);

    const userAgent = normalizeUserAgent(req.headers['user-agent']);

    const geo = this.isTrustedProxyRequest(req)
      ? extractGeoFromHeaders(req)
      : undefined;

    const challenge = extractChallengeFromHeaders(req);

    return { ip, userAgent, geo, challenge };
  }

  private isTrustedProxyRequest(req: Request): boolean {
    const pol = this.policy.get().proxyGeoTrust;

    if (!pol.enabled) return false;

    const allow = new Set(pol.trustedProxyIps.map((x) => normalizeIp(x)));
    if (allow.size === 0) return false;

    const remote = req.socket?.remoteAddress;
    if (!remote) return false;

    const remoteIp = normalizeIp(remote);
    if (!allow.has(remoteIp)) return false;

    const markerName = pol.markerName;
    const markerValue = pol.markerValue;

    const v = req.headers[markerName];
    const got = (
      Array.isArray(v) ? String(v[0] ?? '') : typeof v === 'string' ? v : ''
    ).trim();

    if (!got || got !== markerValue) return false;

    return true;
  }
}
