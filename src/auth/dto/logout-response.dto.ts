import { ApiProperty } from '@nestjs/swagger';

export class LogoutResponseDto {
  @ApiProperty({ example: true, description: 'Статус виходу' })
  loggedOut: boolean;

  @ApiProperty({
    example: '2025-06-07T11:30:00.000Z',
    description: 'Час завершення сесій',
  })
  terminatedAt: string;
}
