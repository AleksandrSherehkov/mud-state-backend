export type FetchSiteValue = 'same-origin' | 'same-site';

export type ProxyGeoTrustPolicy = {
  enabled: boolean;
  trustedProxyIps: string[];
  markerName: string;
  markerValue: string;
};

export type CsrfM2mClientStatus = 'active' | 'disabled';

export type CsrfM2mClientRecord = {
  kid: string;
  secret: string; // хранится НЕ в env, а в secret store (file)
  scopes: string[];
  status: CsrfM2mClientStatus;
  notBefore?: string;
  expiresAt?: string;
};

export type AuthPolicy = {
  refreshCookieName: string;
};

export type CsrfPolicy = {
  enabled: boolean;

  cookieName: string;
  headerName: string;

  trustedOrigins: string[];
  allowNoOriginInProd: boolean;

  enforceFetchSiteInProd: boolean;
  allowedFetchSites: FetchSiteValue[];

  m2m: {
    enabled: boolean;
    replayWindowSec: number;
    redisUrl: string;
    noncePrefix: string;

    secretsFile?: string;
    reloadTtlSec: number;
  };
};

export type AppEnv = 'development' | 'test' | 'production';

export type SecurityPolicy = {
  appEnv: AppEnv;
  isProd: boolean;

  auth: AuthPolicy;
  csrf: CsrfPolicy;
  proxyGeoTrust: ProxyGeoTrustPolicy;
};
