import { ApiProperty } from '@nestjs/swagger';
import { IsJWT, IsNotEmpty } from 'class-validator';

export class RefreshDto {
  @ApiProperty({
    example:
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJzaWQiOiJhM2YxZTViMi0xYzRkLTRlNmYtOWE4Yi0xMjM0NTY3ODkwYWIiLCJqdGkiOiIxNTg2ODg0YS0zYmU1LTRhZjAtOGYxNC05ZGM0M2Y0ZTI3N2QiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJyb2xlIjoiVVNFUiIsImlzcyI6Im11ZC1zdGF0ZSIsImF1ZCI6Im11ZC1hcGkiLCJleHAiOjQ3NDAwMDAwMDB9.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    description: 'Refresh токен (JWT)',
  })
  @IsJWT()
  @IsNotEmpty()
  refreshToken: string;
}
