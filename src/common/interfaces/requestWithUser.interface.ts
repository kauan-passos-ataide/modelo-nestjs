import { Request } from 'express';
import { JwtPayload } from './jwtPayload.interface';

export interface RequestWithUser extends Request {
  user: JwtPayload;
}
