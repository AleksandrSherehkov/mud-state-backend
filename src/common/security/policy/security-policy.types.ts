export type FetchSiteValue = 'same-origin' | 'same-site';

export type ProxyGeoTrustPolicy = {
  enabled: boolean;
  trustedProxyIps: string[]; // normalized IP strings
  markerName: string; // header name lowercased
  markerValue: string; // expected value
};

export type CsrfM2mClient = {
  kid: string;
  secret: string;
  scopes: string[]; // '*' or list of path prefixes
};

export type CsrfPolicy = {
  enabled: boolean;

  // double-submit
  cookieName: string; // default "csrfToken"
  headerName: string; // default "x-csrf-token"

  // origin/referrer policy
  trustedOrigins: string[];
  allowNoOriginInProd: boolean;

  // fetch-site policy
  enforceFetchSiteInProd: boolean;
  allowedFetchSites: FetchSiteValue[];

  // m2m
  m2m: {
    enabled: boolean;
    clients: CsrfM2mClient[];
    replayWindowSec: number;
    redisUrl: string;
    noncePrefix: string;
  };
};
export type AppEnv = 'development' | 'test' | 'production';
export type SecurityPolicy = {
  appEnv: AppEnv;
  isProd: boolean;

  csrf: CsrfPolicy;
  proxyGeoTrust: ProxyGeoTrustPolicy;
};
