import type { Request } from 'express';

type CookieReadOptions = {
  signed?: boolean;
};

export function getCookieString(
  req: Request,
  name: string,
  opts: CookieReadOptions = {},
): string | undefined {
  const r = req as unknown as {
    cookies?: Record<string, unknown>;
    signedCookies?: Record<string, unknown>;
  };

  const signedRaw = r.signedCookies?.[name];

  if (signedRaw === false) return undefined;

  const signed = typeof signedRaw === 'string' ? signedRaw : undefined;

  if (opts.signed) {
    return signed;
  }

  if (signed) return signed;

  const plainRaw = r.cookies?.[name];
  const plain = typeof plainRaw === 'string' ? plainRaw : undefined;

  return plain;
}
