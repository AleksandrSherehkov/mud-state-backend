import * as ipaddr from 'ipaddr.js';

export function normalizeIp(raw?: string | null): string {
  let s = String(raw ?? '').trim();
  if (!s) return '';

  if (s.toLowerCase() === 'unknown') return 'unknown';

  if (s.includes(',')) {
    s = s.split(',')[0].trim();
  }

  const bracket = /^\[([^\]]+)\](?::\d+)?$/.exec(s);
  if (bracket) {
    s = bracket[1].trim();
  }

  if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(s)) {
    s = s.split(':')[0].trim();
  }

  const pct = s.indexOf('%');
  if (pct >= 0) s = s.slice(0, pct).trim();

  // Быстрая валидация
  if (!ipaddr.isValid(s)) {
    return '';
  }

  const addr = ipaddr.parse(s);

  if (addr.kind() === 'ipv6') {
    const v6 = addr as ipaddr.IPv6;
    if (v6.isIPv4MappedAddress()) {
      return v6.toIPv4Address().toString();
    }
  }

  return addr.toNormalizedString();
}
