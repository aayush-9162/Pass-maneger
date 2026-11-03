/**
 * Google ID token verification.
 *
 * The browser (or the extension's OAuth flow) obtains an ID token from Google
 * and hands it here. That token is the entire credential, so everything about
 * it is checked before it is believed:
 *
 *   - **Signature** - RS256 against Google's published keys, fetched from the
 *     JWKS endpoint and cached for as long as Google's `Cache-Control` allows.
 *   - **Issuer, audience, expiry** - `jsonwebtoken` enforces all three; the
 *     audience must be this deployment's own client id, so a token minted for
 *     some other application cannot be replayed here.
 *   - **Verified email** - an unverified address proves nothing about who
 *     controls it.
 *   - **Hosted domain** - the `hd` claim, which Google sets only for Workspace
 *     accounts, must be on the allow-list, and so must the email's domain.
 *     Checking both means a consumer Gmail account cannot get in by having an
 *     address that merely looks right.
 *   - **Nonce**, when the caller supplies one - binds a token to a single
 *     server-issued challenge (step-up), so it cannot be replayed.
 */

import crypto, { type KeyObject } from 'node:crypto';

import jwt, { type JwtPayload } from 'jsonwebtoken';

import { env } from '../config/env';
import { logger } from '../config/logger';
import { ForbiddenError, ServiceUnavailableError, UnauthorizedError } from '../utils/errors';

const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const GOOGLE_ISSUERS: [string, ...string[]] = ['https://accounts.google.com', 'accounts.google.com'];

/** Used when Google omits `Cache-Control`; it never has, but a default beats refetching per sign-in. */
const DEFAULT_KEY_TTL_MS = 60 * 60_000;
/** An unknown `kid` forces a refetch at most this often, so junk tokens cannot make us hammer Google. */
const FORCED_REFRESH_INTERVAL_MS = 60_000;

export interface GoogleIdentity {
  /** Stable Google account id. Survives email changes; the link to a PassM account. */
  subject: string;
  /** Lowercased. */
  email: string;
  givenName: string;
  familyName: string;
  /** When Google issued the token. */
  issuedAt: Date;
}

interface GoogleJwk extends crypto.JsonWebKey {
  kid?: string;
}

let keyCache: { keys: Map<string, KeyObject>; expiresAt: number } | null = null;
let keyFetch: Promise<Map<string, KeyObject>> | null = null;
let lastForcedRefreshAt = 0;

async function fetchSigningKeys(): Promise<Map<string, KeyObject>> {
  let response: Response;
  try {
    response = await fetch(GOOGLE_JWKS_URL, { signal: AbortSignal.timeout(5_000) });
  } catch (error) {
    logger.error('Could not reach Google to fetch sign-in keys', { error });
    throw new ServiceUnavailableError(
      'PassM could not reach Google to verify your sign-in. Check the server has internet access.',
    );
  }

  if (!response.ok) {
    logger.error('Google sign-in key endpoint returned an error', { status: response.status });
    throw new ServiceUnavailableError('Google sign-in is temporarily unavailable. Try again shortly.');
  }

  const body = (await response.json()) as { keys?: GoogleJwk[] };
  const keys = new Map<string, KeyObject>();
  for (const jwk of body.keys ?? []) {
    if (jwk.kty !== 'RSA' || !jwk.kid) continue;
    keys.set(jwk.kid, crypto.createPublicKey({ key: jwk, format: 'jwk' }));
  }

  const maxAge = /max-age=(\d+)/.exec(response.headers.get('cache-control') ?? '')?.[1];
  keyCache = {
    keys,
    expiresAt: Date.now() + (maxAge ? Number(maxAge) * 1000 : DEFAULT_KEY_TTL_MS),
  };
  return keys;
}

async function signingKey(kid: string): Promise<KeyObject | undefined> {
  if (keyCache && keyCache.expiresAt > Date.now()) {
    const cached = keyCache.keys.get(kid);
    if (cached) return cached;

    // A fresh cache without this kid: Google may have rotated early - or the
    // token is junk. Refetch, but rarely.
    if (Date.now() - lastForcedRefreshAt < FORCED_REFRESH_INTERVAL_MS) return undefined;
    lastForcedRefreshAt = Date.now();
  }

  // Concurrent sign-ins share one fetch.
  keyFetch ??= fetchSigningKeys().finally(() => {
    keyFetch = null;
  });
  return (await keyFetch).get(kid);
}

function rejected(reason: string, detail?: Record<string, unknown>): UnauthorizedError {
  logger.warn('Google ID token rejected', { reason, ...detail });
  return new UnauthorizedError('Google sign-in could not be verified. Please try again.');
}

export const googleIdentityService = {
  /** True once a client id is configured; without one nobody can sign in. */
  isConfigured(): boolean {
    return Boolean(env.google.clientId);
  },

  /**
   * Verify a Google ID token and return who it identifies.
   *
   * @param options.nonce Required value of the token's `nonce` claim, when the
   *   token was requested against a server-issued challenge.
   * @throws UnauthorizedError for any token that does not verify,
   *   ForbiddenError for a verified account outside the allowed domains,
   *   ServiceUnavailableError when Google's keys cannot be fetched.
   */
  async verifyIdToken(credential: string, options: { nonce?: string } = {}): Promise<GoogleIdentity> {
    const clientId = env.google.clientId;
    if (!clientId) {
      throw new ServiceUnavailableError(
        'Google sign-in is not configured on this server. Set GOOGLE_CLIENT_ID.',
      );
    }

    const decoded = jwt.decode(credential, { complete: true });
    if (!decoded || typeof decoded.payload === 'string') throw rejected('malformed');
    if (decoded.header.alg !== 'RS256' || !decoded.header.kid) {
      throw rejected('unexpected header', { alg: decoded.header.alg });
    }

    const key = await signingKey(decoded.header.kid);
    if (!key) throw rejected('unknown signing key', { kid: decoded.header.kid });

    let payload: JwtPayload;
    try {
      payload = jwt.verify(credential, key, {
        algorithms: ['RS256'],
        audience: clientId,
        issuer: GOOGLE_ISSUERS,
        // Allows for a little drift between this server's clock and Google's.
        clockTolerance: 30,
      }) as JwtPayload;
    } catch (error) {
      throw rejected('verification failed', { message: (error as Error).message });
    }

    const subject = typeof payload.sub === 'string' ? payload.sub : '';
    const email = typeof payload.email === 'string' ? payload.email.trim().toLowerCase() : '';
    if (!subject || !email) throw rejected('missing subject or email');

    if (payload.email_verified !== true) throw rejected('email not verified', { email });

    if (options.nonce !== undefined && payload.nonce !== options.nonce) {
      throw rejected('nonce mismatch', { email });
    }

    const allowed = env.google.allowedDomains;
    if (allowed.length > 0) {
      const hostedDomain = typeof payload.hd === 'string' ? payload.hd.toLowerCase() : '';
      const emailDomain = email.slice(email.lastIndexOf('@') + 1);

      if (!allowed.includes(hostedDomain) || !allowed.includes(emailDomain)) {
        logger.warn('Google sign-in refused: account outside the allowed domains', {
          email,
          hostedDomain: hostedDomain || null,
        });
        throw new ForbiddenError(
          `Only ${allowed.map((domain) => `@${domain}`).join(' or ')} Google accounts can sign in to PassM.`,
        );
      }
    }

    return {
      subject,
      email,
      givenName: typeof payload.given_name === 'string' ? payload.given_name : '',
      familyName: typeof payload.family_name === 'string' ? payload.family_name : '',
      issuedAt: new Date((payload.iat ?? 0) * 1000),
    };
  },
};
