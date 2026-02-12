import { ApiProperty } from '@nestjs/swagger';

export class TokenResponseDto {
  @ApiProperty({
    example:
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJzaWQiOiJhM2YxZTViMi0xYzRkLTRlNmYtOWE4Yi0xMjM0NTY3ODkwYWIiLCJqdGkiOiIxNTg2ODg0YS0zYmU1LTRhZjAtOGYxNC05ZGM0M2Y0ZTI3N2QiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJyb2xlIjoiVVNFUiIsImlzcyI6Im11ZC1zdGF0ZSIsImF1ZCI6Im11ZC1hcGkiLCJleHAiOjQ3NDAwMDAwMDB9.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    description: 'Access токен (JWT)',
  })
  accessToken: string;

  @ApiProperty({
    example: 'a3f1e5b2-1c4d-4e6f-9a8b-1234567890ab',
    description: 'JWT ID (jti) для refresh токена',
    format: 'uuid',
  })
  jti: string;

  constructor(data: { accessToken: string; jti: string }) {
    this.accessToken = data.accessToken;
    this.jti = data.jti;
  }
}
