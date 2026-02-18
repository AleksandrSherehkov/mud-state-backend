import { Request } from 'express';
import { normalizeIp } from '../net/ip-normalize';
import { createHash } from 'node:crypto';

const MAX_USER_AGENT_LENGTH = 255;

export type RequestGeo = {
  country?: string;
  asn?: number;
  asOrgHash?: string;
};

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

function envBool(name: string, def = false): boolean {
  const v = String(process.env[name] ?? '')
    .trim()
    .toLowerCase();
  if (!v) return def;
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

let TRUSTED_PROXY_IPS_CACHE: Set<string> | null = null;

function getTrustedProxyIps(): Set<string> {
  if (TRUSTED_PROXY_IPS_CACHE) return TRUSTED_PROXY_IPS_CACHE;

  const raw = String(process.env.TRUSTED_PROXY_IPS ?? '');
  const ips = raw
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
    .map((ip) => normalizeIp(ip));

  TRUSTED_PROXY_IPS_CACHE = new Set(ips);
  return TRUSTED_PROXY_IPS_CACHE;
}

function isTrustedProxyRequest(req: Request): boolean {
  if (!envBool('TRUST_PROXY_GEO_HEADERS', false)) return false;

  const allow = getTrustedProxyIps();
  if (allow.size === 0) return false;

  const remote = req.socket?.remoteAddress;
  if (!remote) return false;

  const remoteIp = normalizeIp(remote);
  if (!allow.has(remoteIp)) return false;

  const markerName = String(
    process.env.TRUST_PROXY_GEO_MARKER_NAME ?? 'x-ingress-auth',
  ).toLowerCase();
  const markerValue = String(
    process.env.TRUST_PROXY_GEO_MARKER_VALUE ?? '1',
  ).trim();

  const v = req.headers[markerName];
  const got = (
    Array.isArray(v) ? String(v[0] ?? '') : typeof v === 'string' ? v : ''
  ).trim();

  if (!got || got !== markerValue) return false;

  return true;
}

export function extractRequestInfo(req: Request): {
  ip: string;
  userAgent: string;
  geo?: RequestGeo;
} {
  const rawIp = req.ip || (Array.isArray(req.ips) ? req.ips[0] : '') || '';
  const ip = normalizeIp(rawIp);

  const userAgent = normalizeUserAgent(req.headers['user-agent']);

  const geo = isTrustedProxyRequest(req)
    ? extractGeoFromHeaders(req)
    : undefined;

  return { ip, userAgent, geo };
}
