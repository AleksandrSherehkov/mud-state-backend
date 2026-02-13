import { Role } from '@prisma/client';

type Access = 'PUBLIC' | 'AUTHENTICATED' | readonly Role[];

type BuildDescriptionArgs = {
  access?: Access;
  sideEffects?: string | string[];
  notes?: string | string[];
};

function normalizeLines(v?: string | string[]): string[] {
  if (!v) return [];
  if (Array.isArray(v)) return v.flatMap((x) => String(x).split('\n'));
  return String(v).split('\n');
}

function accessToLine(access?: Access): string {
  if (!access) return '';

  if (access === 'PUBLIC' || access === 'AUTHENTICATED') {
    return `Доступ: ${access}.`;
  }

  const roles = access as readonly Role[];
  const rolesText = roles.length ? roles.join(', ') : 'AUTHENTICATED';
  return `Доступ: ${rolesText}.`;
}

export function buildDescription({
  access,
  sideEffects,
  notes,
}: BuildDescriptionArgs): string {
  const parts: string[] = [];

  const accessLine = accessToLine(access);
  if (accessLine) parts.push(accessLine);

  const seLines = normalizeLines(sideEffects).filter(Boolean);
  if (seLines.length) {
    parts.push(['Side effects:', ...seLines.map((x) => `- ${x}`)].join('\n'));
  }

  const noteLines = normalizeLines(notes).filter(Boolean);
  if (noteLines.length) {
    parts.push(['Notes:', ...noteLines.map((x) => `- ${x}`)].join('\n'));
  }

  return parts.join('\n\n');
}
