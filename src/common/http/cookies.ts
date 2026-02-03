import type { Request } from 'express';

export function getCookieString(
  req: Request,
  name: string,
): string | undefined {
  const r = req as unknown as {
    cookies?: Record<string, unknown>;
    signedCookies?: Record<string, unknown>;
  };

  const signed = r.signedCookies?.[name] as string | undefined;
  if (typeof signed === 'string') return signed;

  const plain = r.cookies?.[name];
  if (typeof plain === 'string') return plain;

  return undefined;
}
