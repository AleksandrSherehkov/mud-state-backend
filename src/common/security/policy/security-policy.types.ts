export type FetchSiteValue = 'same-origin' | 'same-site';

export type ProxyGeoTrustPolicy = {
  enabled: boolean;
  trustedProxyIps: string[];
  markerName: string;
  markerValue: string;
};

export type CsrfM2mClient = {
  kid: string;
  secret: string;
  scopes: string[];
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
