import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response } from 'express';
import { stringify } from 'querystring';
import { atoms, Request as AuthnzRequest } from 'auth-nz';
import { AuthService } from './auth.service';

@Injectable()
export class AuthorizationMiddleware implements NestMiddleware {
  constructor(private authService: AuthService) {}

  // eslint-disable-next-line @typescript-eslint/ban-types
  async use(req: Request, res: Response, next: Function): Promise<void> {
    const request: AuthnzRequest = atoms.getRequest(req);
    const {
      error,
      clientError,
      redirectUri,
      ...meta
    } = await atoms.AuthorizationRequest.authorizeRequest(
      request,
      this.authService.findClient.bind(this.authService),
      { development: process.env.NODE_ENV !== 'production' },
    );

    if (clientError) {
      res.locals.authorizationServer = { error: clientError };
    } else if (error) {
      res.redirect(`${redirectUri}?${stringify({ ...error })}`);
      return;
    } else {
      res.locals.authorizationServer = { redirectUri, ...meta };
    }
    next();
  }
}
