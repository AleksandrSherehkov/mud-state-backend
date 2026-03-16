import { Injectable } from '@nestjs/common';
import { createHash } from 'node:crypto';

import { normalizeIp } from 'src/common/net/ip-normalize';
import { SecurityPolicyService } from './security-policy.service';

export type TrustedProxyGeo = {
  country?: string;
  asn?: number;
  asOrgHash?: string;
};

type HeaderMap = Record<string, unknown>;

type ProxyAwareRequest = {
  headers?: HeaderMap;
  socket?: unknown;
  connection?: unknown;
};

function firstNonEmptyString(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined;
  const s = v.trim();
  return s || undefined;
}

function getHeaderString(headers: HeaderMap | undefined, name: string): string {
  if (!headers || typeof headers !== 'object') return '';

  const raw = headers[name.toLowerCase()];
  if (typeof raw === 'string') return raw.trim();
  if (Array.isArray(raw) && typeof raw[0] === 'string') {
    return raw[0].trim();
  }

  return '';
}

function getRemoteIp(req: ProxyAwareRequest): string | undefined {
  const socketRemote =
    req.socket && typeof req.socket === 'object'
      ? (req.socket as { remoteAddress?: unknown }).remoteAddress
      : undefined;

  const connectionRemote =
    req.connection && typeof req.connection === 'object'
      ? (req.connection as { remoteAddress?: unknown }).remoteAddress
      : undefined;

  return (
    firstNonEmptyString(socketRemote) ?? firstNonEmptyString(connectionRemote)
  );
}

function normalizeCountry(v?: string): string | undefined {
  const s = (v ?? '').trim().toUpperCase();
  if (/^[A-Z]{2}$/.test(s)) return s;
  return undefined;
}

function normalizeAsn(v?: string): number | undefined {
  const s = (v ?? '').trim();
  const m = /^(?:AS)?(\d{1,10})$/i.exec(s);
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
  return createHash('sha256').update(v, 'utf8').digest('hex');
}

@Injectable()
export class TrustedProxyGeoService {
  constructor(private readonly policy: SecurityPolicyService) {}

  isTrustedProxyRequest(req: ProxyAwareRequest): boolean {
    const pol = this.policy.get().proxyGeoTrust;

    if (!pol.enabled) return false;

    const allow = new Set(pol.trustedProxyIps.map((x) => normalizeIp(x)));
    if (allow.size === 0) return false;

    const remote = getRemoteIp(req);
    if (!remote) return false;

    const remoteIp = normalizeIp(remote);
    if (!allow.has(remoteIp)) return false;

    const got = getHeaderString(req.headers, pol.markerName);
    if (!got) return false;

    return got === pol.markerValue;
  }

  extractTrustedGeo(req: ProxyAwareRequest): TrustedProxyGeo | undefined {
    if (!this.isTrustedProxyRequest(req)) return undefined;

    const headers = req.headers;

    const cfCountry = getHeaderString(headers, 'cf-ipcountry');

    const xCountry =
      getHeaderString(headers, 'x-geo-country') ||
      getHeaderString(headers, 'x-country') ||
      getHeaderString(headers, 'x-forwarded-country');

    const xAsn =
      getHeaderString(headers, 'x-geo-asn') ||
      getHeaderString(headers, 'x-asn');

    const xAsOrg =
      getHeaderString(headers, 'x-geo-asn-org') ||
      getHeaderString(headers, 'x-asn-org');

    const country = normalizeCountry(cfCountry || xCountry || undefined);
    const asn = normalizeAsn(xAsn || undefined);

    const asOrgRaw = normalizeAsOrg(xAsOrg || undefined);
    const asOrgHash = asOrgRaw ? hashOrg(asOrgRaw) : undefined;

    if (!country && !asn && !asOrgHash) return undefined;

    return { country, asn, asOrgHash };
  }

  getTrustedAsn(req: ProxyAwareRequest): number | undefined {
    return this.extractTrustedGeo(req)?.asn;
  }
}
