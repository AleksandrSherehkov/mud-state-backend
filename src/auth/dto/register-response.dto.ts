import { ApiProperty } from '@nestjs/swagger';
import { Role } from '@prisma/client';

export class RegisterResponseDto {
  @ApiProperty({
    example: '550e8400-e29b-41d4-a716-446655440000',
    description: 'Унікальний ID користувача',
    format: 'uuid',
  })
  id: string;

  @ApiProperty({
    example: 'user@example.com',
    description: 'Email користувача',
  })
  email: string;

  @ApiProperty({
    example: Role.USER,
    enum: Role,
    description: 'Роль користувача',
  })
  role: Role;

  @ApiProperty({
    example: '2025-05-31T14:16:08.682Z',
    description: 'Дата створення',
    type: String,
    format: 'date-time',
  })
  createdAt: string;
  @ApiProperty({
    example:
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJzaWQiOiJhM2YxZTViMi0xYzRkLTRlNmYtOWE4Yi0xMjM0NTY3ODkwYWIiLCJqdGkiOiIxNTg2ODg0YS0zYmU1LTRhZjAtOGYxNC05ZGM0M2Y0ZTI3N2QiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJyb2xlIjoiVVNFUiIsImlzcyI6Im11ZC1zdGF0ZSIsImF1ZCI6Im11ZC1hcGkiLCJleHAiOjQ3NDAwMDAwMDB9.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    description: 'Access токен (JWT)',
  })
  accessToken: string;

  @ApiProperty({
    example: 'a3f1e5b2-1c4d-4e6f-9a8b-1234567890ab',
    description: 'JWT ID (jti) для refresh токена',
  })
  jti: string;

  constructor(data: {
    id: string;
    email: string;
    role: Role;
    createdAt: Date;
    accessToken: string;
    jti: string;
  }) {
    this.id = data.id;
    this.email = data.email;
    this.role = data.role;
    this.createdAt = data.createdAt.toISOString();
    this.accessToken = data.accessToken;
    this.jti = data.jti;
  }
}
