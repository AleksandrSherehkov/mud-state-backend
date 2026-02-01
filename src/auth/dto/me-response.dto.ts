import { ApiProperty } from '@nestjs/swagger';
import { Role } from '@prisma/client';

export class MeResponseDto {
  @ApiProperty({ example: 'clx123...', description: 'ID користувача' })
  id: string;

  @ApiProperty({
    example: 'user@example.com',
    description: 'Email користувача',
  })
  email: string;

  @ApiProperty({
    example: Role.USER,
    enum: Role,
  })
  role: Role;

  @ApiProperty({
    example: '2025-05-31T14:16:08.682Z',
    description: 'Дата створення',
    type: String,
    format: 'date-time',
  })
  createdAt: Date;

  constructor(data: {
    id: string;
    email: string;
    role: Role;
    createdAt: Date;
  }) {
    this.id = data.id;
    this.email = data.email;
    this.role = data.role;
    this.createdAt = data.createdAt;
  }
}
