export type AuthGeoContext = {
  country?: string;
  asn?: number;
  asOrgHash?: string;
};

export type AuthChallengeContext = {
  nonce?: string;
  solution?: string;
};

export type AuthRequestContext = {
  ip?: string;
  userAgent?: string;
  geo?: AuthGeoContext;

  challenge?: AuthChallengeContext;
};
