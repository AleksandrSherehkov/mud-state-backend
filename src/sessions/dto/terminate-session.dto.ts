import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsUUID } from 'class-validator';

export class TerminateSessionDto {
  @ApiProperty({
    description: 'ID (UUID) сесії, яку потрібно завершити',
    format: 'uuid',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @Transform(({ value }) => {
    if (typeof value !== 'string') {
      return '';
    }
    return value.trim();
  })
  @IsUUID('4')
  sessionId: string;
}
