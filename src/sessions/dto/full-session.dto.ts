import { ApiProperty } from '@nestjs/swagger';

export class FullSessionDto {
  @ApiProperty({
    example: 'a3f1e5b2-1c4d-4e6f-9a8b-1234567890ab',
    format: 'uuid',
  })
  id: string;

  @ApiProperty({
    example: '192.168.x.x',
    description: 'Маскована IP-адреса сесії',
  })
  ip: string;

  @ApiProperty({
    example: 'Chrome',
    description: 'Скорочена family user-agent без повного сирого рядка',
  })
  userAgent: string;

  @ApiProperty({ example: true })
  isActive: boolean;

  @ApiProperty({
    example: '2025-05-31T14:00:00.000Z',
    type: String,
    format: 'date-time',
  })
  startedAt: string;

  @ApiProperty({
    example: null,
    nullable: true,
    type: String,
    format: 'date-time',
  })
  endedAt: string | null;

  constructor(data: {
    id: string;
    ip: string;
    userAgent: string;
    isActive: boolean;
    startedAt: string;
    endedAt: string | null;
  }) {
    this.id = data.id;
    this.ip = data.ip;
    this.userAgent = data.userAgent;
    this.isActive = data.isActive;
    this.startedAt = data.startedAt;
    this.endedAt = data.endedAt;
  }
}
