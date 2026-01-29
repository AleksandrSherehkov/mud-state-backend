import { ApiProperty } from '@nestjs/swagger';
import { IsJWT, IsNotEmpty } from 'class-validator';

export class RefreshDto {
  @ApiProperty({ example: 'jwt.refresh.token', description: 'Refresh токен' })
  @IsJWT()
  @IsNotEmpty()
  refreshToken: string;
}
