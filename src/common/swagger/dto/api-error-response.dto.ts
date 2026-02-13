import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class ApiErrorResponseDto {
  @ApiProperty({ example: 401 })
  statusCode: number;

  @ApiProperty({
    example: 'Необхідна авторизація',
    oneOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' } }],
  })
  message: string | string[];

  @ApiProperty({ example: 'Unauthorized' })
  error: string;

  @ApiProperty({
    example: '2026-02-02T00:00:00.000Z',
    type: String,
    format: 'date-time',
  })
  timestamp: string;

  @ApiProperty({ example: '/api/v1/auth/me' })
  path: string;

  @ApiPropertyOptional({ example: 'req_01J2ABCDEF...' })
  requestId?: string;
}
