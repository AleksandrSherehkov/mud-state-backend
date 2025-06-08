export type Tokens = {
  accessToken: string;
  refreshToken: string;
  jti: string;
};

export type JwtPayload = {
  sub: string;
  email: string;
  jti: string;
  role: 'ADMIN' | 'MODERATOR' | 'USER';
  sid: string;
};
