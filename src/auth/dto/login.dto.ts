import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, MaxLength } from 'class-validator';

export class LoginDto {
  @ApiProperty({
    example: 'user@example.com',
    description: 'Email користувача',
  })
  @IsString()
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    example: 'StrongPassword123',
    description:
      'Пароль згідно політики безпеки (довжина/вимоги задаються через ENV)',
  })
  @MaxLength(72)
  @IsString()
  @IsNotEmpty()
  password: string;
}
