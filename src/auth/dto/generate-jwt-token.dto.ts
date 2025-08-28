import { IsEmail, IsString } from 'class-validator';

export class GenerateJwtToken {
  @IsString()
  id: string;

  @IsEmail()
  email: string;

  @IsString()
  role: string;
}
