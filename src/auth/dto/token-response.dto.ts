import { ApiProperty } from '@nestjs/swagger';

export class TokenResponseDto {
  @ApiProperty({ example: 'access.jwt.token' })
  accessToken: string;

  @ApiProperty({ example: 'refresh.jwt.token' })
  refreshToken: string;
  @ApiProperty({
    example: 'uuid',
    description: 'a3f1e5b2-1c4d-4e6f-9a8b-1234567890ab',
  })
  jti: string;
}
