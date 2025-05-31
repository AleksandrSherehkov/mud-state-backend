import { ApiProperty } from '@nestjs/swagger';
import { IsJWT, IsNotEmpty } from 'class-validator';

export class RefreshTokenDto {
  @ApiProperty({ example: 'refresh.jwt.token' })
  @IsJWT()
  @IsNotEmpty()
  refreshToken: string;
}
