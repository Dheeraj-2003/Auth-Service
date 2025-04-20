import { IsEmail, IsEnum, IsNotEmpty, IsOptional, Length } from 'class-validator';
import { Role } from 'src/credentials/role.enum';

export class RegisterDto {
  @IsNotEmpty()
  name: string;

  @IsEmail()
  @IsNotEmpty()
  email: string;

  @Length(8,24)
  @IsNotEmpty()
  password: string;

  @IsEnum(Role)
  @IsOptional()
  role: Role;
}
