import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsIP, IsNotEmpty, IsString } from 'class-validator';

export class TerminateSessionDto {
  @ApiProperty({ example: '192.168.0.1', description: 'IP адреса сесії' })
  @Transform(({ value }: { value: unknown }) => {
    if (typeof value !== 'string') return '';
    return value.trim();
  })
  @IsString()
  @IsIP()
  @IsNotEmpty()
  ip: string;

  @ApiProperty({
    example: 'Mozilla/5.0...',
    description: 'User-Agent сесії',
  })
  @Transform(({ value }: { value: unknown }) => {
    if (typeof value !== 'string') return '';
    return value.trim();
  })
  @IsString()
  @IsNotEmpty()
  userAgent: string;
}
