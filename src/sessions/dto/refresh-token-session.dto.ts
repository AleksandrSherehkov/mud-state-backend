import { ApiProperty } from '@nestjs/swagger';

export class RefreshTokenSessionDto {
  @ApiProperty({ example: 'uuid' })
  jti: string;

  @ApiProperty({ example: '192.168.0.1' })
  ip: string;

  @ApiProperty({ example: 'Mozilla/5.0...' })
  userAgent: string;

  @ApiProperty({ example: '2025-05-31T14:50:00.000Z' })
  createdAt: string;
}
