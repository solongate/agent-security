/**
 * Signing in, from a terminal, against the operator's own identity provider.
 *
 * THE PROVIDER SHOWS THE PAGE, NOT US. This used to be a device flow against
 * SolonGate's own API, finished on a page the hosted dashboard served — and that
 * endpoint took the person's address out of the request body without verifying
 * it, so possession of a user code was the whole authorisation. It worked
 * because the dashboard was its only caller and had already signed somebody in.
 * With no dashboard it would have been the only way in and it verified nothing.
 *
 * So the flow is RFC 8628 against the IDENTITY PROVIDER (OAuth 2.0 Device
 * Authorization Grant), which is what `gh`, `az` and `gcloud` do and for the
 * same reason: a CLI cannot receive a redirect, and a browser is the only place
 * a person should ever type a password. The provider authenticates them, the
 * provider issues an ID token, and this exchanges that token at /auth/session —
 * where the address comes off the VERIFIED token's claims and nothing reads a
 * request body. The hole closes by construction rather than by a check.
 *
 * Nothing here prints. The caller renders the code and drives the poll loop, so
 * the dataroom does not have to fight this writing over its frame.
 *
 * The Go CLI carries the same flow in internal/api/device.go; the two are read
 * together when either changes.
 */
import { spawn } from 'node:child_process';
import { DEFAULT_API_URL } from './client.js';

export interface DeviceStart {
  /**
   * What the person types at the provider. SHOWN rather than hidden in the URL:
   * verification_uri_complete is a convenience the browser may or may not
   * honour, and somebody reading the code off a laptop to type into a phone
   * needs to be able to see it.
   */
  userCode: string;
  /** Where they type it, with the code in it when the provider offers that. */
  verifyUrl: string;
  /** The same address without the code, for the line that says where to go. */
  verifyUrlPlain: string;
  intervalMs: number;
  expiresAt: number;

  /** The provider's token endpoint, which the poll needs and nothing else has. */
  tokenUrl: string;
  clientId: string;
  deviceCode: string;
}

export interface DevicePoll {
  status: 'pending' | 'approved' | 'expired' | 'denied';
  apiKey?: string;
  project?: string;
  user?: string;
  email?: string;
  /** Why a terminal status happened, when the provider or the service said. */
  message?: string;
}

/** Best-effort browser open. No-op on failure (headless / missing opener). */
export function openBrowser(url: string): void {
  if (!url.trim()) return;
  try {
    const cmd = process.platform === 'win32' ? 'cmd' : process.platform === 'darwin' ? 'open' : 'xdg-open';
    const args = process.platform === 'win32' ? ['/c', 'start', '""', url] : [url];
    const child = spawn(cmd, args, { stdio: 'ignore', detached: true });
    child.on('error', () => {});
    child.unref();
  } catch {
    /* the URL and the code are printed either way */
  }
}

/** Thrown when the service has no identity provider to sign in against. */
export class NoProviderError extends Error {
  constructor() {
    super(
      'this SolonGate service has no identity provider configured, so there is nobody to sign in against.\n' +
        '  Whoever runs it sets SG_OIDC_ISSUER (and SG_OIDC_CLIENT_ID) and restarts it.',
    );
    this.name = 'NoProviderError';
  }
}

/**
 * A form post that decodes JSON whatever the status.
 *
 * RFC 6749 puts the error in the BODY with a 400: `authorization_pending` — the
 * normal state for most of this flow — arrives that way, so treating the status
 * as the answer would turn every poll into a failure.
 */
async function postForm(endpoint: string, form: Record<string, string>): Promise<any> {
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams(form).toString(),
    signal: AbortSignal.timeout(20_000),
  });
  return res.json();
}

/** Renders an OAuth error the way a person can act on. */
function oauthErrText(code: string, description?: string): string {
  return description?.trim() ? `${description} (${code})` : code;
}

/**
 * Reads the address and name out of an ID token FOR DISPLAY.
 *
 * It verifies nothing and must not be used for anything that decides access:
 * the service verified this token against the provider's keys before it issued
 * a credential, and that is the check that counts.
 */
function idTokenDisplayName(idToken: string): { email?: string; user?: string } {
  try {
    const [, payload] = idToken.split('.');
    if (!payload) return {};
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    // The same order the service reads them in, so the name printed here is the
    // account the credential actually belongs to.
    const email = [claims.email, claims.upn, claims.preferred_username].find(
      (c: unknown): c is string => typeof c === 'string' && c.includes('@'),
    );
    return { email, user: claims.name || email };
  } catch {
    return {};
  }
}

/**
 * Opens a pairing request.
 *
 * It runs BEFORE there is a credential, so the API URL is passed explicitly
 * rather than resolved — resolution would fail with "not logged in" on exactly
 * the machine that is trying to log in.
 */
export async function startDeviceLogin(apiUrl: string = DEFAULT_API_URL): Promise<DeviceStart> {
  const cfgRes = await fetch(`${apiUrl}/api/v1/auth/config`, { signal: AbortSignal.timeout(20_000) });
  if (!cfgRes.ok) throw new Error(`HTTP ${cfgRes.status}`);
  const cfg = (await cfgRes.json()) as {
    oidc?: boolean;
    issuer?: string;
    client_id?: string;
    scopes?: string[];
  };

  if (!cfg.oidc || !cfg.issuer) throw new NoProviderError();
  if (!cfg.client_id) {
    throw new Error(
      'this SolonGate service names an identity provider but no client id, and a device\n' +
        '  sign-in cannot be started without one. Whoever runs it sets SG_OIDC_CLIENT_ID.',
    );
  }

  const issuer = cfg.issuer.replace(/\/+$/, '');
  const discoRes = await fetch(`${issuer}/.well-known/openid-configuration`, {
    signal: AbortSignal.timeout(20_000),
  });
  if (!discoRes.ok) {
    throw new Error(`the identity provider at ${issuer} answered ${discoRes.status} for its discovery document`);
  }
  const disco = (await discoRes.json()) as {
    device_authorization_endpoint?: string;
    token_endpoint?: string;
  };
  if (!disco.device_authorization_endpoint) {
    throw new Error(
      `the identity provider at ${issuer} does not advertise the device authorization grant,\n` +
        '  which is the only sign-in a terminal can complete',
    );
  }

  const scopes = cfg.scopes?.length ? cfg.scopes : ['openid', 'profile', 'email'];
  const body = await postForm(disco.device_authorization_endpoint, {
    client_id: cfg.client_id,
    scope: scopes.join(' '),
  });
  if (body.error) {
    throw new Error('the identity provider refused the request: ' + oauthErrText(body.error, body.error_description));
  }
  if (!body.device_code || !body.user_code) {
    throw new Error('the identity provider answered the device request without a code');
  }

  // Floors, not defaults. RFC 8628 says five seconds when the provider does not,
  // and a provider asking to be polled faster than two is asking to rate-limit
  // the person signing in.
  const interval = Number(body.interval) >= 2 ? Number(body.interval) : 5;
  const expires = Number(body.expires_in) > 0 ? Number(body.expires_in) : 600;

  return {
    userCode: body.user_code,
    verifyUrl: body.verification_uri_complete || body.verification_uri || '',
    verifyUrlPlain: body.verification_uri || '',
    intervalMs: interval * 1000,
    expiresAt: Date.now() + expires * 1000,
    tokenUrl: disco.token_endpoint ?? '',
    clientId: cfg.client_id,
    deviceCode: body.device_code,
  };
}

/**
 * Asks the provider once whether the person has finished, and on success trades
 * what it gets for a SolonGate credential.
 *
 * A TRANSPORT FAILURE IS PENDING, NOT AN ERROR. The person is in a browser
 * during this loop and a dropped frame or a 502 must not end a sign-in they are
 * halfway through; `expiresAt` is what ends it. Only the provider saying so ends
 * it early.
 */
export async function pollDeviceLogin(apiUrl: string, start: DeviceStart): Promise<DevicePoll> {
  let tok: any;
  try {
    tok = await postForm(start.tokenUrl, {
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: start.deviceCode,
      client_id: start.clientId,
    });
  } catch {
    return { status: 'pending' };
  }

  switch (tok.error) {
    case undefined:
    case '':
      // An absent token is also how a provider or two spell "nothing yet".
      if (!tok.id_token) return { status: 'pending' };
      break;
    case 'authorization_pending':
    // slow_down asks for a longer interval. The caller's loop is already at the
    // provider's stated one and an extra round trip costs nobody anything.
    case 'slow_down':
      return { status: 'pending' };
    case 'expired_token':
      return { status: 'expired' };
    case 'access_denied':
      return { status: 'denied', message: 'the sign-in was refused at the identity provider' };
    default:
      return { status: 'denied', message: oauthErrText(tok.error, tok.error_description) };
  }

  // The provider has vouched for them. THIS SERVICE HAS NOT YET — the token goes
  // to /auth/session, which verifies the signature against the provider's own
  // keys and takes the address from the claims.
  let session: any;
  try {
    const res = await fetch(`${apiUrl}/api/v1/auth/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ access_token: tok.id_token }),
      signal: AbortSignal.timeout(20_000),
    });
    session = await res.json().catch(() => ({}));
    if (!res.ok) {
      // The provider said yes and this service said no. Terminal: polling again
      // cannot change it, and the usual cause is a token minted for a different
      // audience than SG_OIDC_CLIENT_ID names.
      const why = session?.error?.message || `HTTP ${res.status}`;
      return { status: 'denied', message: 'the identity provider signed you in, but SolonGate refused the token: ' + why };
    }
  } catch (e) {
    return { status: 'pending' };
  }

  if (!session?.api_key) {
    return { status: 'denied', message: 'SolonGate accepted the sign-in but issued no credential for this account' };
  }

  const who = idTokenDisplayName(tok.id_token);
  return {
    status: 'approved',
    apiKey: session.api_key,
    project: session.project?.name,
    ...who,
  };
}
