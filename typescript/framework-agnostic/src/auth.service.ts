import { Injectable } from '@nestjs/common';
import {
  Client,
  AuthorizationCode,
  AuthorizationRequestMeta,
  Request as AuthnzRequest,
} from 'auth-nz';
import { randomBytes } from 'crypto';

@Injectable()
export class AuthService {
  clients: Client[] = [
    {
      clientId: 'cb894e06',
      clientSecret: 'a28d04fdb176b2d1a6be95e8',
      redirectUri: 'https://oauth.pstmn.io/v1/callback',
    },
  ];

  authorizationCodes: AuthorizationCode[] = [];

  async findClient(clientId: Client['clientId']): Promise<Client> {
    // Finding a client in a real world scenario is usually an async operation
    return this.clients.find((client) => client.clientId === clientId);
  }

  async findAuthorizationCode(): Promise<AuthorizationCode> {
    return {} as AuthorizationCode;
  }

  async createAuthorizationCode(
    meta: AuthorizationRequestMeta,
    _req: AuthnzRequest,
  ): Promise<AuthorizationCode['code']> {
    const code = randomBytes(16).toString('hex');
    const authorizationCode: AuthorizationCode = {
      code,
      // use your preferred way of obtaining the user's id, most commonly it's
      // req.session.user.id
      userId: 1,
      expiresAt: Date.now() + 60000, // now + 1 min
      clientId: meta.clientId,
      redirectUri: meta.redirectUri,
      scope: meta.scope,
      codeChallenge: meta.codeChallenge,
      codeChallengeMethod: meta.codeChallengeMethod,
    };
    console.log('Authorization code: ', authorizationCode);
    this.authorizationCodes.push(authorizationCode);
    return code;
  }
}
