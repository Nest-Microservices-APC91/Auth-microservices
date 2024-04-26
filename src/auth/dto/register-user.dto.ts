import {
  IsEmail,
  IsString,
  IsStrongPassword,
  MinLength,
} from 'class-validator';

export class RegisterUserDto {
  @IsString()
  @MinLength(1)
  name: string;

  @IsEmail()
  @IsString()
  email: string;

  @IsString()
  @IsStrongPassword()
  password: string;
}
