import { ApiProperty } from '@nestjs/swagger';

export class FullSessionDto {
  @ApiProperty({ example: 'sess_xyz789' })
  id: string;

  @ApiProperty({ example: '192.168.1.1' })
  ip: string;

  @ApiProperty({ example: 'Mozilla/5.0...' })
  userAgent: string;

  @ApiProperty({ example: true })
  isActive: boolean;

  @ApiProperty({ example: '2025-05-31T14:00:00.000Z' })
  startedAt: string;

  @ApiProperty({ example: null })
  endedAt: string | null;
}
