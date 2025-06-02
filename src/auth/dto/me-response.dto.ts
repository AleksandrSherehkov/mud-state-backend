import { ApiProperty } from '@nestjs/swagger';

export class MeResponseDto {
  @ApiProperty({ example: 'clx123...', description: 'ID користувача' })
  id: string;

  @ApiProperty({
    example: 'user@example.com',
    description: 'Email користувача',
  })
  email: string;

  @ApiProperty({ example: 'USER', enum: ['ADMIN', 'MODERATOR', 'USER'] })
  role: 'ADMIN' | 'MODERATOR' | 'USER';

  @ApiProperty({
    example: '2025-05-31T14:16:08.682Z',
    description: 'Дата створення',
  })
  createdAt: Date;
}
