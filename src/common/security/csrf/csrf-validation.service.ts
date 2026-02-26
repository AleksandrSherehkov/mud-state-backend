import { ForbiddenException, Injectable } from '@nestjs/common';
import type { Request } from 'express';

import { SecurityPolicyService } from '../policy/security-policy.service';
import { OriginPolicyService } from './origin-policy.service';
import { FetchSitePolicyService } from './fetch-site-policy.service';
import { DoubleSubmitCsrfService } from './double-submit.service';
import { CsrfM2mHmacService } from './m2m-hmac.service';
import { CsrfM2mReplayService } from './m2m-replay.service';

function isSafeMethod(method: string): boolean {
  const m = (method || '').toUpperCase();
  return m === 'GET' || m === 'HEAD' || m === 'OPTIONS';
}

type BrowserSignals = { hasOriginSignals: boolean; hasFetchSite: boolean };

@Injectable()
export class CsrfValidationService {
  constructor(
    private readonly policy: SecurityPolicyService,
    private readonly originPolicy: OriginPolicyService,
    private readonly fetchSite: FetchSitePolicyService,
    private readonly doubleSubmit: DoubleSubmitCsrfService,
    private readonly m2m: CsrfM2mHmacService,
    private readonly replay: CsrfM2mReplayService,
  ) {}

  async assertRequestAllowed(req: Request): Promise<void> {
    if (isSafeMethod(req.method)) return;

    const pol = this.policy.get().csrf;
    if (!pol.enabled) return;

    const m2mOk = await this.tryHandleM2m(req);
    if (m2mOk) return;

    this.assertBrowserPolicy(req);

    this.doubleSubmit.assertValid(req);
  }
  assertCsrfIssuanceAllowed(req: Request): void {
    const snap = this.policy.get();
    const pol = snap.csrf;

    if (!pol.enabled) return;
    if (!snap.isProd) return;

    const trusted = pol.trustedOrigins;

    if (trusted.length === 0) {
      throw new ForbiddenException(
        'CSRF validation failed (trusted origins not configured)',
      );
    }

    const { hasOriginSignals, hasFetchSite } = this.getBrowserSignals(req);

    if (!hasOriginSignals && !hasFetchSite) {
      throw new ForbiddenException('CSRF validation failed (non-browser)');
    }

    if (hasOriginSignals) {
      this.originPolicy.assertAllowed(req);
      if (pol.enforceFetchSiteInProd) {
        this.fetchSite.assertAllowedIfPresent(req);
      }
      return;
    }

    if (pol.enforceFetchSiteInProd) {
      this.fetchSite.assertAllowedWhenOnlySignal(req);
    }
  }
  private async tryHandleM2m(req: Request): Promise<boolean> {
    const m2mHeaders = this.m2m.parseHeaders(req);
    if (!m2mHeaders) return false;

    const { kid, ts, nonce, sign } = m2mHeaders;

    this.m2m.assertWindow(ts);

    const client = this.m2m.findClientOrThrow(kid);
    this.m2m.assertScopeAllowed(client, req);

    const nonceKey = await this.replay.assertNonceOnce(kid, ts, nonce);
    try {
      const expected = this.m2m.computeExpected(client, req, kid, ts, nonce);
      this.m2m.assertSignature(expected, sign);
      return true;
    } catch (e) {
      await this.replay.rollbackNonce(nonceKey);
      throw e;
    }
  }

  private assertBrowserPolicy(req: Request): void {
    const pol = this.policy.get().csrf;
    const trusted = pol.trustedOrigins;

    const { hasOriginSignals, hasFetchSite } = this.getBrowserSignals(req);
    const isProd = this.policy.get().isProd;

    if (isProd) {
      this.assertProdBrowserPolicy(
        req,
        trusted,
        hasOriginSignals,
        hasFetchSite,
      );
      return;
    }

    if (trusted.length > 0 && hasOriginSignals) {
      this.originPolicy.assertAllowed(req);
    }
  }

  private assertProdBrowserPolicy(
    req: Request,
    trusted: string[],
    hasOriginSignals: boolean,
    hasFetchSite: boolean,
  ): void {
    const pol = this.policy.get().csrf;

    if (trusted.length === 0) {
      throw new ForbiddenException(
        'CSRF validation failed (trusted origins not configured)',
      );
    }

    if (hasOriginSignals) {
      this.originPolicy.assertAllowed(req);
      if (pol.enforceFetchSiteInProd) {
        this.fetchSite.assertAllowedIfPresent(req);
      }
      return;
    }

    if (hasFetchSite) {
      if (pol.enforceFetchSiteInProd) {
        this.fetchSite.assertAllowedWhenOnlySignal(req);
      }
      return;
    }

    if (!pol.allowNoOriginInProd) {
      throw new ForbiddenException('CSRF validation failed (non-browser)');
    }
  }

  private getBrowserSignals(req: Request): BrowserSignals {
    const hasOriginSignals = Boolean(
      (req.header('origin') || '').trim() ||
      (req.header('referer') || '').trim(),
    );
    const hasFetchSite = Boolean((req.header('sec-fetch-site') || '').trim());
    return { hasOriginSignals, hasFetchSite };
  }
}
