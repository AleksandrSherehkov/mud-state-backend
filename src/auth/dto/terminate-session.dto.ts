import { IsIP, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class TerminateSessionDto {
  @ApiProperty({ example: '192.168.0.1', description: 'IP адреса сесії' })
  @IsIP()
  @IsNotEmpty()
  ip: string;

  @ApiProperty({
    example: 'Mozilla/5.0...',
    description: 'User-Agent сесії',
  })
  @IsNotEmpty()
  userAgent: string;
}
