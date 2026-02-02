import type { Request } from 'express';

export function getCookieString(
  req: Request,
  name: string,
): string | undefined {
  const cookies = (req as unknown as { cookies?: Record<string, unknown> })
    .cookies;
  const v = cookies?.[name];
  return typeof v === 'string' ? v : undefined;
}
