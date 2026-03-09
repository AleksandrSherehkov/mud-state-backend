import { Session } from '@prisma/client';

import { FullSessionDto } from './dto/full-session.dto';

type PrismaSessionView = Pick<
  Session,
  'id' | 'ip' | 'userAgent' | 'isActive' | 'startedAt' | 'endedAt'
>;

type UserAgentFamilyRule = {
  family: string;
  match: (value: string) => boolean;
};

const USER_AGENT_FAMILY_RULES: readonly UserAgentFamilyRule[] = [
  {
    family: 'Edge',
    match: (value) => value.includes('edg/'),
  },
  {
    family: 'Opera',
    match: (value) => includesAny(value, ['opr/', 'opera']),
  },
  {
    family: 'Chrome',
    match: (value) => value.includes('chrome/'),
  },
  {
    family: 'Firefox',
    match: (value) => value.includes('firefox/'),
  },
  {
    family: 'Safari',
    match: (value) => value.includes('safari/') && !value.includes('chrome/'),
  },
  {
    family: 'PostmanRuntime',
    match: (value) => value.includes('postmanruntime/'),
  },
  {
    family: 'Insomnia',
    match: (value) => value.includes('insomnia/'),
  },
  {
    family: 'curl',
    match: (value) => value.includes('curl/'),
  },
  {
    family: 'wget',
    match: (value) => value.includes('wget/'),
  },
  {
    family: 'okhttp',
    match: (value) => value.includes('okhttp/'),
  },
  {
    family: 'axios',
    match: (value) => value.includes('axios/'),
  },
  {
    family: 'node-fetch',
    match: (value) => value.includes('node-fetch'),
  },
  {
    family: 'undici',
    match: (value) => value.includes('undici'),
  },
  {
    family: 'Mozilla-compatible',
    match: (value) => value.includes('mozilla/'),
  },
] as const;

function includesAny(source: string, needles: readonly string[]): boolean {
  return needles.some((needle) => source.includes(needle));
}

export function maskSessionIp(ip?: string | null): string {
  const raw = (ip ?? '').trim();
  if (!raw) return '';

  if (raw.includes('.')) {
    const parts = raw.split('.');
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.x.x`;
    }
  }

  if (raw.includes(':')) {
    const parts = raw.split(':').filter(Boolean);
    if (parts.length >= 4) {
      return `${parts.slice(0, 4).join(':')}:*:*:*:*`;
    }

    return 'ipv6';
  }

  return 'masked';
}

export function detectUserAgentFamily(userAgent?: string | null): string {
  const ua = (userAgent ?? '').trim();
  if (!ua) return 'Unknown';

  const lower = ua.toLowerCase();
  const detected = USER_AGENT_FAMILY_RULES.find(({ match }) => match(lower));

  return detected?.family ?? 'Other';
}

export function toFullSessionDto(session: PrismaSessionView): FullSessionDto {
  return new FullSessionDto({
    id: session.id,
    ip: maskSessionIp(session.ip),
    userAgent: detectUserAgentFamily(session.userAgent),
    isActive: session.isActive,
    startedAt: session.startedAt.toISOString(),
    endedAt: session.endedAt?.toISOString() ?? null,
  });
}
