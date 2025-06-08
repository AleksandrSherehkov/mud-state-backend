export type UserFromJwt = {
  userId: string;
  email: string;
  role: 'ADMIN' | 'MODERATOR' | 'USER';
  sid: string;
};
