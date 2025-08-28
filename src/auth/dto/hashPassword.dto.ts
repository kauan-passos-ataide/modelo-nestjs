import { IsString } from 'class-validator';

export class HashPassword {
  @IsString()
  password: string;

  @IsString()
  hash: string;
}
