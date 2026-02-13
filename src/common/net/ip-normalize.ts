export function normalizeIp(raw?: string | null): string {
  let ip: string = String(raw ?? '').trim();

  if (ip.includes(',')) {
    ip = ip.split(',')[0].trim();
  }

  if (ip.startsWith('::ffff:')) {
    ip = ip.slice(7);
  }

  if (/^\d+\.\d+\.\d+\.\d+:\d+$/.test(ip)) {
    ip = ip.split(':')[0];
  }

  const bracketMatch = /^\[([^\]]+)\](?::\d+)?$/.exec(ip);
  if (bracketMatch) {
    ip = bracketMatch[1];
  }

  return ip;
}
