import { IsIP, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class TerminateSessionDto {
  @ApiProperty({ example: '192.168.0.1', description: 'IP адреса сесії' })
  @IsIP('4')
  @IsNotEmpty()
  ip: string;
}
