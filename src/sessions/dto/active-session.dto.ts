import { ApiProperty } from '@nestjs/swagger';

export class ActiveSessionDto {
  @ApiProperty({ example: 'sess_abc123' })
  id: string;

  @ApiProperty({ example: '192.168.1.1' })
  ip: string;

  @ApiProperty({ example: 'Mozilla/5.0...' })
  userAgent: string;

  @ApiProperty({ example: '2025-05-31T14:00:00.000Z' })
  startedAt: string;
}
