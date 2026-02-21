import { ForbiddenException, Injectable, OnModuleInit } from '@nestjs/common';
import { readFileSync, statSync } from 'node:fs';
import type { CsrfM2mClientRecord } from '../policy/security-policy.types';
import { SecurityPolicyService } from '../policy/security-policy.service';

function isIsoDate(v: unknown): v is string {
  if (typeof v !== 'string') return false;
  const t = Date.parse(v);
  return Number.isFinite(t);
}

function nowMs(): number {
  return Date.now();
}

function isKid(v: unknown): v is string {
  return typeof v === 'string' && /^[a-zA-Z0-9_-]{1,32}$/.test(v);
}

function isScopes(v: unknown): v is string[] {
  return (
    Array.isArray(v) &&
    v.every((x) => typeof x === 'string' && x.trim().length > 0) &&
    v.length > 0
  );
}

function normalizeScopes(scopes: string[]): string[] {
  const list = scopes.map((s) => s.trim()).filter(Boolean);
  return list.length === 0 ? ['*'] : list;
}

function isStatus(v: unknown): v is 'active' | 'disabled' {
  return v === 'active' || v === 'disabled';
}

type Cache = {
  loadedAtMs: number;
  mtimeMs: number;
  clients: CsrfM2mClientRecord[];
};

@Injectable()
export class CsrfM2mClientsService implements OnModuleInit {
  private cache: Cache | null = null;

  constructor(private readonly policy: SecurityPolicyService) {}
  onModuleInit(): void {
    const p = this.policy.get();
    const m2m = p.csrf.m2m;

    if (p.isProd && m2m.enabled) {
      if (!m2m.secretsFile) {
        throw new Error('CSRF M2M secrets file is required in production');
      }

      this.loadClientsOrThrowStartup();
    }
  }

  private loadClientsOrThrowStartup(): void {
    try {
      // если JSON битый/файл не читается — упадём при старте
      this.loadClients();
    } catch {
      throw new Error('CSRF M2M secrets file is not readable or invalid JSON');
    }
  }

  getActiveClientOrThrow(kid: string): CsrfM2mClientRecord {
    const client = this.getActiveClient(kid);
    if (!client)
      throw new ForbiddenException('CSRF validation failed (non-browser)');
    return client;
  }

  getActiveClient(kid: string): CsrfM2mClientRecord | null {
    const clients = this.loadClients();
    const found = clients.find((c) => c.kid === kid);
    if (!found) return null;

    if (found.status !== 'active') return null;

    const nb = found.notBefore ? Date.parse(found.notBefore) : undefined;
    if (nb && Number.isFinite(nb) && nowMs() < nb) return null;

    const exp = found.expiresAt ? Date.parse(found.expiresAt) : undefined;
    if (exp && Number.isFinite(exp) && nowMs() >= exp) return null;

    return found;
  }

  private loadClients(): CsrfM2mClientRecord[] {
    const pol = this.policy.get().csrf.m2m;
    const isProd = this.policy.get().isProd;

    // ✅ В dev допускаем отсутствие файла (M2M просто не работает)
    if (!isProd && !pol.secretsFile) return [];

    const path = pol.secretsFile;
    if (!path) return [];

    const ttlMs = pol.reloadTtlSec * 1000;

    try {
      const st = statSync(path);
      const mtimeMs = st.mtimeMs;

      const cached = this.cache;
      const freshByTtl = cached && nowMs() - cached.loadedAtMs < ttlMs;
      const sameMtime = cached?.mtimeMs === mtimeMs;

      if (cached && freshByTtl && sameMtime) return cached.clients;

      const raw = readFileSync(path, 'utf8');

      const parsed: unknown = JSON.parse(raw);

      if (!Array.isArray(parsed)) {
        throw new TypeError('CSRF M2M secrets must be an array');
      }

      const clients: CsrfM2mClientRecord[] = parsed
        .map((x) =>
          x && typeof x === 'object' ? (x as Record<string, unknown>) : null,
        )
        .filter((x): x is Record<string, unknown> => Boolean(x))
        .map((o) => {
          const kid = o['kid'];
          const secret = o['secret'];
          const scopes = o['scopes'];
          const status = o['status'];

          const notBefore = o['notBefore'];
          const expiresAt = o['expiresAt'];

          if (!isKid(kid)) return null;

          if (typeof secret !== 'string' || secret.trim().length < 32)
            return null;

          if (!isScopes(scopes)) return null;
          if (!isStatus(status)) return null;

          if (notBefore !== undefined && !isIsoDate(notBefore)) return null;
          if (expiresAt !== undefined && !isIsoDate(expiresAt)) return null;
          const nb = typeof notBefore === 'string' ? notBefore : undefined;
          const exp = typeof expiresAt === 'string' ? expiresAt : undefined;

          return {
            kid,
            secret: secret.trim(),
            scopes: normalizeScopes(scopes),
            status,
            ...(nb ? { notBefore: nb } : {}),
            ...(exp ? { expiresAt: exp } : {}),
          } satisfies CsrfM2mClientRecord;
        })
        .filter((x): x is CsrfM2mClientRecord => Boolean(x));

      const byKid = new Map<string, CsrfM2mClientRecord>();
      for (const c of clients) byKid.set(c.kid, c);

      const deduped = Array.from(byKid.values());

      this.cache = {
        loadedAtMs: nowMs(),
        mtimeMs,
        clients: deduped,
      };

      return deduped;
    } catch {
      throw new ForbiddenException('CSRF validation failed (non-browser)');
    }
  }
}
