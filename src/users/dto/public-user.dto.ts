import { ApiProperty } from '@nestjs/swagger';
import { Role } from '@prisma/client';

export class PublicUserDto {
  @ApiProperty({
    example: '550e8400-e29b-41d4-a716-446655440000',
    description: 'Унікальний ID користувача',
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

  constructor(data: {
    id: string;
    email: string;
    role: Role;
    createdAt: Date;
  }) {
    this.id = data.id;
    this.email = data.email;
    this.role = data.role;
    this.createdAt = data.createdAt.toISOString();
  }
}
