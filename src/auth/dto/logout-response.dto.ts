import { ApiProperty } from '@nestjs/swagger';

export class LogoutResponseDto {
  @ApiProperty({ example: true, description: 'Статус виходу' })
  loggedOut: boolean;

  @ApiProperty({
    example: '2025-06-07T11:30:00.000Z',
    type: String,
    format: 'date-time',
    nullable: true,
    description: 'Час завершення сесій',
  })
  terminatedAt: string | null;

  constructor(data: { loggedOut: boolean; terminatedAt: string | null }) {
    this.loggedOut = data.loggedOut;
    this.terminatedAt = data.terminatedAt;
  }
}
