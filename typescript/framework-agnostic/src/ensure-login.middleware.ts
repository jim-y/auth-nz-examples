import { Request, Response } from 'express';

export function ensureLogin(req: Request, res: Response, next: Function) {
  // TODO implement user authentication using session or jwt-auth or whatever
  next();
}
