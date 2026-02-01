import { ApiProperty } from '@nestjs/swagger';

export class ActiveSessionDto {
  @ApiProperty({
    format: 'uuid',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  id: string;

  @ApiProperty({ example: '192.168.1.1' })
  ip: string;

  @ApiProperty({ example: 'Mozilla/5.0...' })
  userAgent: string;

  @ApiProperty({ example: '2025-05-31T14:00:00.000Z' })
  startedAt: string;
}
