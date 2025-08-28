import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { HashPassword } from './dto/hashPassword.dto';
import { GenerateJwtToken } from './dto/generate-jwt-token.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from '../common/interfaces/jwtPayload.interface';
import { PrismaService } from '../prisma/prisma.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private prisma: PrismaService,
    private configService: ConfigService,
  ) {}

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 10);
  }

  async comparePassword({ password, hash }: HashPassword): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  async generateJwtAccessToken(data: GenerateJwtToken): Promise<string> {
    return this.jwtService.signAsync(data, {
      secret: this.configService.get<string>(
        'JWT_SECRET_ACCESS_TOKEN',
      ) as string,
      expiresIn: '15 min',
    });
  }

  async generateJwtRefreshToken(data: GenerateJwtToken): Promise<string> {
    return this.jwtService.signAsync(data, {
      secret: this.configService.get<string>(
        'JWT_SECRET_REFRESH_TOKEN',
      ) as string,
      expiresIn: '7d',
    });
  }

  async getPayloadFromAccessToken(token: string): Promise<JwtPayload> {
    const payload: JwtPayload = await this.jwtService.verifyAsync(token, {
      secret: this.configService.get<string>(
        'JWT_SECRET_ACCESS_TOKEN',
      ) as string,
    });
    return payload;
  }

  async getPayloadFromRefreshToken(token: string): Promise<JwtPayload> {
    const payload: JwtPayload = await this.jwtService.verifyAsync(token, {
      secret: this.configService.get<string>(
        'JWT_SECRET_REFRESH_TOKEN',
      ) as string,
    });
    return payload;
  }
}
