export type AuthGeoContext = {
  country?: string;
  asn?: number;
  asOrgHash?: string;
};

export type AuthRequestContext = {
  ip?: string;
  userAgent?: string;
  geo?: AuthGeoContext;
};
