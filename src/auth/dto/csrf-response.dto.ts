import { ApiProperty } from '@nestjs/swagger';

export class CsrfResponseDto {
  @ApiProperty({
    example: '550e8400-e29b-41d4-a716-446655440000',
    description: 'CSRF token для передачі у заголовку x-csrf-token',
  })
  csrfToken: string;

  constructor(data: { csrfToken: string }) {
    this.csrfToken = data.csrfToken;
  }
}
