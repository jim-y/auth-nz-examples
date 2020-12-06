import * as express from 'express';
import * as session from 'express-session';
import * as bearerToken from 'express-bearer-token';
import * as hbs from 'hbs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

// Debugging
require('source-map-support').install();
process.on('unhandledRejection', console.log);

import {
  createServer,
  AuthorizationServer,
  AuthorizationServerOptions,
  Client,
  AuthorizationCode,
  AuthorizationRequestMeta,
  AccessToken,
  TokenRequestMeta,
} from 'auth-nz';

const app = express();
const port = 3000;

/**
 * ===========================
 *       Mock Cache/DB
 * ===========================
 */
interface IMockCache {
  clients: Client[];
  authorizationCodes: AuthorizationCode[];
  accessTokens: any[];
}
const cache: IMockCache = {
  clients: [
    {
      clientId: 'test-client',
      clientSecret: '5fb0b59c347dfa47f4e617e5',
      redirectUri: 'https://oauth.pstmn.io/v1/callback',
    },
  ],
  authorizationCodes: [],
  accessTokens: [],
};

const as: AuthorizationServer = createServer({
  // The validateAuthorizationRequest middleware requires a callback to return a
  // Promise with a Client. If the Promise fulfills with a Client the middleware
  // can validate the client. Otherwise, if the Promise rejects or returns with
  // null an error is raised You can provide this function as a parameter for
  // the middleware too
  findClient: async clientId =>
    cache.clients.find((record: Client) => record.clientId === clientId),

  findAuthorizationCode: async code =>
    cache.authorizationCodes.find(
      (record: AuthorizationCode) => record.code === code
    ),

  development: process.env.NODE_ENV !== 'production',
} as AuthorizationServerOptions);

// handlebars view engine
hbs.registerPartials(path.join(__dirname, 'views/partials'));
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
  })
);

/**
 * ===========================
 *        Middlewares
 * ===========================
 */

// 4) It's up to you how you authenticate your users. Here, we say a user is
//    already authenticated if the session has a user object in which case we
//    can call the next middleware. If a user is not authenticated redirect her
//    UA to a login form. Before the redirect, save the original url for a later
//    redirect -> we really just need the querystring but it's easier like this
const ensureLogin = (req, res, next) => {
  if (req.session.user) {
    return next();
  }
  req.session.redirectTo = req.originalUrl;
  res.redirect(`/oauth/login`);
};

/**
 * ===========================
 *          OAuth
 * ===========================
 */

app.get(
  // 1) The Client will start the OAuth -authorization code- flow by calling
  //    this endpoint with the following querystring parameters
  //      - response_type REQUIRED
  //      - client_id REQUIRED
  //      - redirect_uri OPTIONAL
  //      - scope OPTIONAL
  //      - state RECOMMENDED
  '/oauth/authorize',

  // 2) The provider needs to validate the request per the protocol. Even before challenging
  //    the user to authenticate. This middleware requires you to provide a callback to validate
  //    the client. Maybe the Client isn't even authorized to use the authorization_code flow in
  //    which case there is not need for user authentication
  as.validateAuthorizationRequest(),

  // 3) If the authorization request and the client is valid the provider needs to check if the
  //    user is authenticated or not. If not, you need to authenticate her
  ensureLogin,

  // 7) Rendering the consent form dialog. The user allows or denies giving access for the Client
  (req, res) => {
    res.locals = {
      title: 'Dialog',
      error: (req as any).session?.authorizationServer?.error,
    };
    res.render('dialog');
  }
);

// 8) The consent form action calls this endpoint with a decision (allow/deny). It up to you how
//    handle allow/deny values. The onDecision middleware requires a callback to return with an
//    authorization code or undefined. If it returns an authorization code then it will redirect
//    the user's UA to the redirect_uri with the authorization code or if the callback returns
//    undefined it will handle it as an oauth error
app.post(
  '/oauth/authorize/decision',
  ensureLogin,
  as.onDecision(async (meta: AuthorizationRequestMeta, req) => {
    console.log('onDecision', meta);
    if (req.body.consent) {
      const code = uuidv4();
      // Persist the code to a cache. This is usually an async operation, so onDecision assumes
      // the cb to return a Promise
      const authorizationCode: AuthorizationCode = {
        code,
        clientId: meta.clientId,
        redirectUri: meta.redirectUri,
        userId: req.session.user.id,
        expiresAt: Date.now() + 10 * 60000, // now + 10 mins
        scope: meta.scope,
        codeChallenge: meta.codeChallenge,
        codeChallengeMethod: meta.codeChallengeMethod,
      };
      cache.authorizationCodes.push(authorizationCode);
      return code;
    }
  })
);

// 9) With the authorization code, the Client can now exchange the code for an access_token
app.post(
  '/oauth/token',
  as.validateTokenRequest(),
  as.onValidToken(async (meta: TokenRequestMeta, req) => {
    console.log('onValidToken', meta);
    const ttl = 1800000;
    const accessToken: AccessToken = {
      token: uuidv4(),
      expiresAt: Date.now() + ttl, // now + 30 minutes
      ttl,
    };
    cache.accessTokens.push(accessToken);

    // We need to delete the authorizationCode from the cache after use
    const authorizationCodeIdx = cache.authorizationCodes.findIndex(
      (record: AuthorizationCode) => record.code === meta.authorizationCode.code
    );
    if (authorizationCodeIdx > -1)
      cache.authorizationCodes.splice(authorizationCodeIdx, 1);

    return accessToken;
  })
);

/**
 * ===========================
 *       Authentication
 * ===========================
 */

// 5) If the user is not yet authenticated you show him a login form
//    You can skip this EP and render the login form right from the ensureLogin middleware
//    if you choose so
app.get('/oauth/login', (req, res) => {
  res.locals = {
    title: 'Login',
  };
  res.render('login');
});

// 6) The login form will submit to this endpoint. This is the place where you'll need to
//    set a valid security context for the user. In this example this is done via setting
//    a user object on the session
//    Redirect the flow to re-start the authorization flow
app.post('/login', (req: any, res) => {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) return res.sendStatus(403);

  req.session.user = {
    email,
    password,
    id: uuidv4(),
  };

  res.redirect(req.session.redirectTo);
});

/**
 * ===========================
 *       Protected API
 * ===========================
 */

app.get('/api/protected', bearerToken(), (req, res) => {
  if (!req.token) {
    return res.sendStatus(401);
  }

  const accessToken: AccessToken = cache.accessTokens.find(
    (record: AccessToken) => record.token === req.token
  );

  if (!accessToken || Date.now() > accessToken.expiresAt) {
    return res.sendStatus(401);
  }

  res.sendStatus(200);
});

app.listen(port, () =>
  console.log(`Example app listening at http://localhost:${port}`)
);
