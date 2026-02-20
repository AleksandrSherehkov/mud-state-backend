import { ForbiddenException, Injectable } from '@nestjs/common';
import type { Request } from 'express';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { SecurityPolicyService } from '../policy/security-policy.service';
import type { CsrfM2mClientRecord } from '../policy/security-policy.types';
import { CsrfM2mClientsService } from './m2m-clients.service';

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function base64Url(buf: Buffer): string {
  return buf
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
}

@Injectable()
export class CsrfM2mHmacService {
  constructor(
    private readonly policy: SecurityPolicyService,
    private readonly clients: CsrfM2mClientsService,
  ) {}

  parseHeaders(
    req: Request,
  ): { kid: string; ts: number; nonce: string; sign: string } | null {
    const kid = (req.header('x-csrf-m2m-kid') ?? '').trim();
    const tsRaw = (req.header('x-csrf-m2m-ts') ?? '').trim();
    const nonce = (req.header('x-csrf-m2m-nonce') ?? '').trim();
    const sign = (req.header('x-csrf-m2m-sign') ?? '').trim();

    if (!kid && !tsRaw && !nonce && !sign) return null;

    if (!kid || !tsRaw || !nonce || !sign) {
      throw new ForbiddenException('CSRF validation failed (non-browser)');
    }

    if (!/^[a-zA-Z0-9_-]{1,32}$/.test(kid)) {
      throw new ForbiddenException('CSRF validation failed (m2m_kid)');
    }
    if (!/^[a-zA-Z0-9_-]{16,128}$/.test(nonce)) {
      throw new ForbiddenException('CSRF validation failed (m2m_nonce)');
    }

    const ts = Number(tsRaw);
    if (!Number.isFinite(ts) || !Number.isInteger(ts)) {
      throw new ForbiddenException('CSRF validation failed (m2m_ts)');
    }

    return { kid, ts, nonce, sign };
  }

  assertWindow(ts: number): void {
    const p = this.policy.get().csrf.m2m;
    const drift = Math.abs(nowSec() - ts);
    if (drift > p.replayWindowSec) {
      throw new ForbiddenException('CSRF validation failed (m2m_ts_window)');
    }
  }

  findClientOrThrow(kid: string): CsrfM2mClientRecord {
    // ✅ секреты/metadata теперь из secret store, а не из env/policy snapshot
    return this.clients.getActiveClientOrThrow(kid);
  }

  assertScopeAllowed(client: CsrfM2mClientRecord, req: Request): void {
    if (client.scopes.includes('*')) return;

    const path = req.path || '';
    const ok = client.scopes.some(
      (prefix) => prefix && path.startsWith(prefix),
    );
    if (!ok) throw new ForbiddenException('CSRF validation failed (m2m_scope)');
  }

  computeExpected(
    client: CsrfM2mClientRecord,
    req: Request,
    kid: string,
    ts: number,
    nonce: string,
  ): string {
    const canonical = `${kid}.${ts}.${nonce}.${req.method.toUpperCase()}.${req.originalUrl}`;
    return base64Url(
      createHmac('sha256', client.secret).update(canonical).digest(),
    );
  }

  assertSignature(expected: string, provided: string): void {
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(provided, 'utf8');
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      throw new ForbiddenException('CSRF validation failed (non-browser)');
    }
  }
}
