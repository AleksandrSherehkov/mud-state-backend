import Redis from 'ioredis';
import { inspect } from 'node:util';

export type SharedRedisCreateParams = {
  url: string | null | undefined;
  strict: boolean;
  connectTimeoutMs: number;
  name?: string;
};

function safeErrMessage(err: unknown): string {
  if (err == null) return 'unknown';

  if (err instanceof Error) return err.message || err.name;

  if (typeof err === 'string') return err;
  if (
    typeof err === 'number' ||
    typeof err === 'boolean' ||
    typeof err === 'bigint'
  ) {
    return String(err);
  }

  try {
    return JSON.stringify(err);
  } catch {
    try {
      return inspect(err, { depth: 4, breakLength: 120 });
    } catch {
      return 'unknown';
    }
  }
}

function nameSuffix(name?: string): string {
  const n = String(name ?? '').trim();
  return n ? ` (${n})` : '';
}

function missingUrlMessage(name?: string): string {
  // no nested templates
  return `REDIS: missing url${nameSuffix(name)} (strict=true)`;
}

function disabledMissingUrlMessage(name?: string): string {
  return `[redis] disabled${nameSuffix(name)}: missing url (strict=false)`;
}

function connectFailedStrictMessage(
  p: SharedRedisCreateParams,
  errMsg: string,
): string {
  return `REDIS: connect failed${nameSuffix(p.name)} strict=true timeoutMs=${p.connectTimeoutMs}: ${errMsg}`;
}

function connectFailedNonStrictMessage(
  p: SharedRedisCreateParams,
  errMsg: string,
): string {
  return `[redis] connect failed${nameSuffix(p.name)}: strict=false timeoutMs=${p.connectTimeoutMs}: ${errMsg}. Redis features disabled.`;
}

function safeDisconnect(client: Redis): void {
  try {
    client.disconnect();
  } catch {
    // ignore
  }
}

function normalizeUrl(url: string | null | undefined): string {
  return String(url ?? '').trim();
}

export async function createRedisClientOrNull(
  p: SharedRedisCreateParams,
): Promise<Redis | null> {
  const url = normalizeUrl(p.url);

  if (!url) {
    if (p.strict) throw new Error(missingUrlMessage(p.name));

    console.warn(disabledMissingUrlMessage(p.name));
    return null;
  }

  const client = new Redis(url, {
    lazyConnect: true,
    enableOfflineQueue: false,
    maxRetriesPerRequest: 1,
    connectTimeout: p.connectTimeoutMs,
  });

  try {
    await client.connect();
    return client;
  } catch (err) {
    const msg = safeErrMessage(err);
    safeDisconnect(client);

    if (p.strict) {
      throw new Error(connectFailedStrictMessage(p, msg));
    }

    console.warn(connectFailedNonStrictMessage(p, msg));
    return null;
  }
}
