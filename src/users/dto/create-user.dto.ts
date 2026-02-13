import { IsEmail, IsNotEmpty, IsString, Validate } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { PasswordPolicyValidator } from 'src/common/security/validators/password-policy.validator';

export class CreateUserDto {
  @ApiProperty({ example: 'user@example.com' })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    example: 'StrongPassword123',
    description:
      'Пароль згідно політики безпеки (довжина/вимоги задаються через ENV)',
  })
  @IsString()
  @IsNotEmpty()
  @Validate(PasswordPolicyValidator)
  password: string;
}
