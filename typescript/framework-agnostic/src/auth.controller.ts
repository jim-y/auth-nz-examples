import { Controller, Get, Req, Render, Post, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { atoms, AuthorizationRequestMeta } from 'auth-nz';
import { Request, Response } from 'express';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('oauth/authorize')
  @Render('dialog')
  async getAuthorization(
    @Req() _req: Request,
    @Res() res: Response,
  ): Promise<any> {
    // We do not want to leak the client (clientSecret) to the dialog.
    // Except the client, other information is ok to "leak"
    // In other examples the meta is stored in the session but this example
    // tries to use as less dependencies as it can
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { client, ...meta } = res.locals.authorizationServer;
    return { ...meta, payload: JSON.stringify(meta) };
  }

  @Post('oauth/authorize/decision')
  async onDecision(@Req() req: Request, @Res() res: Response): Promise<any> {
    const authorizationRequestMeta: AuthorizationRequestMeta = JSON.parse(
      req.body.meta,
    );
    const { qs } = (await atoms.AuthorizationRequest.validateAuthorizationCode(
      atoms.getRequest(req),
      this.authService.createAuthorizationCode.bind(this.authService),
      authorizationRequestMeta,
    )) as any;

    res.redirect(`${authorizationRequestMeta.redirectUri}?${qs}`);
  }
}
