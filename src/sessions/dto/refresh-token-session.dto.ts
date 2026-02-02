import { ApiProperty } from '@nestjs/swagger';

export class RefreshTokenSessionDto {
  @ApiProperty({
    example: 'a3f1e5b2-1c4d-4e6f-9a8b-1234567890ab',
    format: 'uuid',
  })
  jti: string;

  @ApiProperty({ example: '192.168.0.1' })
  ip: string;

  @ApiProperty({ example: 'Mozilla/5.0...' })
  userAgent: string;

  @ApiProperty({
    example: '2025-05-31T14:00:00.000Z',
    type: String,
    format: 'date-time',
  })
  startedAt: string;
}
