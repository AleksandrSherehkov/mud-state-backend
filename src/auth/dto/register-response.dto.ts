import { ApiProperty } from '@nestjs/swagger';
import { PublicUserDto } from 'src/users/dto/public-user.dto';

export class RegisterResponseDto extends PublicUserDto {
  @ApiProperty({ example: 'access.jwt.token' })
  accessToken: string;

  @ApiProperty({ example: 'refresh.jwt.token' })
  refreshToken: string;

  @ApiProperty({ example: 'uuid', description: 'JWT ID' })
  jti: string;
}
