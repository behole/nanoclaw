/**
 * Credential proxy for container isolation.
 * Containers connect here instead of directly to the Anthropic API.
 * The proxy injects real credentials so containers never see them.
 *
 * Two auth modes:
 *   API key:  Proxy injects x-api-key on every request.
 *   OAuth:    Container CLI exchanges its placeholder token for a temp
 *             API key via /api/oauth/claude_cli/create_api_key.
 *             Proxy injects real OAuth token on that exchange request;
 *             subsequent requests carry the temp key which is valid as-is.
 *
 * OAuth auto-refresh:
 *   When the proxy gets a 401 from upstream in OAuth mode, it reads the
 *   refresh token from ~/.claude/.credentials.json, exchanges it for a
 *   new access token, and retries the request. A mutex ensures only one
 *   refresh happens at a time.
 */
import { createServer, Server } from 'http';
import { request as httpsRequest } from 'https';
import { request as httpRequest, RequestOptions } from 'http';
import fs from 'fs';
import path from 'path';
import os from 'os';

import { readEnvFile } from './env.js';
import { logger } from './logger.js';

export type AuthMode = 'api-key' | 'oauth';

export interface ProxyConfig {
  authMode: AuthMode;
}

const OAUTH_CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e';
const DEFAULT_REFRESH_URL = 'https://console.anthropic.com/v1/oauth/token';

interface OAuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

function getCredentialsPath(envOverride?: string): string {
  return envOverride || path.join(os.homedir(), '.claude', '.credentials.json');
}

function readCredentials(credPath: string): OAuthTokens | null {
  try {
    const data = JSON.parse(fs.readFileSync(credPath, 'utf-8'));
    const oauth = data.claudeAiOauth;
    if (oauth?.refreshToken) {
      return {
        accessToken: oauth.accessToken,
        refreshToken: oauth.refreshToken,
        expiresAt: oauth.expiresAt,
      };
    }
  } catch {
    // Missing or malformed credentials file
  }
  return null;
}

function writeCredentials(credPath: string, tokens: OAuthTokens): void {
  let data: Record<string, unknown> = {};
  try {
    data = JSON.parse(fs.readFileSync(credPath, 'utf-8'));
  } catch {
    // Start fresh
  }
  data.claudeAiOauth = {
    ...((data.claudeAiOauth as Record<string, unknown>) || {}),
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    expiresAt: tokens.expiresAt,
  };
  fs.writeFileSync(credPath, JSON.stringify(data, null, 2));
}

function updateEnvFile(newToken: string, envFilePath?: string): void {
  const envFile = envFilePath || path.join(process.cwd(), '.env');
  try {
    let content = fs.readFileSync(envFile, 'utf-8');
    content = content.replace(
      /^CLAUDE_CODE_OAUTH_TOKEN=.*/m,
      `CLAUDE_CODE_OAUTH_TOKEN=${newToken}`,
    );
    fs.writeFileSync(envFile, content);
  } catch {
    // .env may not exist; non-critical
  }
}

function refreshOAuthToken(
  refreshToken: string,
  refreshUrl: string,
): Promise<OAuthTokens> {
  const url = new URL(refreshUrl);
  const isHttps = url.protocol === 'https:';
  const doRequest = isHttps ? httpsRequest : httpRequest;
  const body = JSON.stringify({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: OAUTH_CLIENT_ID,
  });

  return new Promise((resolve, reject) => {
    const req = doRequest(
      {
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname,
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          if (res.statusCode !== 200) {
            reject(new Error(`Refresh failed: ${res.statusCode} ${Buffer.concat(chunks).toString()}`));
            return;
          }
          try {
            const data = JSON.parse(Buffer.concat(chunks).toString());
            resolve({
              accessToken: data.accessToken || data.access_token,
              refreshToken: data.refreshToken || data.refresh_token,
              expiresAt: data.expiresAt || data.expires_at || Date.now() + 86400000,
            });
          } catch (e) {
            reject(new Error(`Failed to parse refresh response: ${e}`));
          }
        });
      },
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

export function startCredentialProxy(
  port: number,
  host = '127.0.0.1',
): Promise<Server> {
  const secrets = readEnvFile([
    'ANTHROPIC_API_KEY',
    'CLAUDE_CODE_OAUTH_TOKEN',
    'ANTHROPIC_AUTH_TOKEN',
    'ANTHROPIC_BASE_URL',
    'OAUTH_CREDENTIALS_PATH',
    'OAUTH_REFRESH_URL',
    'OAUTH_ENV_FILE_PATH',
  ]);

  const authMode: AuthMode = secrets.ANTHROPIC_API_KEY ? 'api-key' : 'oauth';
  let oauthToken =
    secrets.CLAUDE_CODE_OAUTH_TOKEN || secrets.ANTHROPIC_AUTH_TOKEN;

  const credentialsPath = getCredentialsPath(secrets.OAUTH_CREDENTIALS_PATH);
  const refreshUrl = secrets.OAUTH_REFRESH_URL || DEFAULT_REFRESH_URL;
  const envFilePath = secrets.OAUTH_ENV_FILE_PATH;

  // Mutex for token refresh — only one refresh at a time
  let refreshInProgress: Promise<void> | null = null;

  async function ensureFreshToken(): Promise<void> {
    if (refreshInProgress) {
      await refreshInProgress;
      return;
    }

    refreshInProgress = (async () => {
      try {
        const creds = readCredentials(credentialsPath);
        if (!creds?.refreshToken) {
          logger.warn('No refresh token available, cannot auto-refresh');
          return;
        }

        logger.info('OAuth token expired, refreshing...');
        const newTokens = await refreshOAuthToken(creds.refreshToken, refreshUrl);

        oauthToken = newTokens.accessToken;
        writeCredentials(credentialsPath, newTokens);
        updateEnvFile(newTokens.accessToken, envFilePath);

        logger.info({ expiresAt: new Date(newTokens.expiresAt).toISOString() },
          'OAuth token refreshed successfully');
      } finally {
        refreshInProgress = null;
      }
    })();

    await refreshInProgress;
  }

  const upstreamUrl = new URL(
    secrets.ANTHROPIC_BASE_URL || 'https://api.anthropic.com',
  );
  const isHttps = upstreamUrl.protocol === 'https:';
  const makeRequest = isHttps ? httpsRequest : httpRequest;

  function forwardRequest(
    body: Buffer,
    incomingHeaders: Record<string, string>,
    method: string,
    urlPath: string,
  ): Promise<{ statusCode: number; headers: Record<string, string>; body: Buffer }> {
    return new Promise((resolve, reject) => {
      const headers: Record<string, string | number | string[] | undefined> = {
        ...incomingHeaders,
        host: upstreamUrl.host,
        'content-length': body.length,
      };

      delete headers['connection'];
      delete headers['keep-alive'];
      delete headers['transfer-encoding'];

      if (authMode === 'api-key') {
        delete headers['x-api-key'];
        headers['x-api-key'] = secrets.ANTHROPIC_API_KEY;
      } else {
        if (headers['authorization']) {
          delete headers['authorization'];
          if (oauthToken) {
            headers['authorization'] = `Bearer ${oauthToken}`;
          }
        }
      }

      const upstream = makeRequest(
        {
          hostname: upstreamUrl.hostname,
          port: upstreamUrl.port || (isHttps ? 443 : 80),
          path: urlPath,
          method,
          headers,
        } as RequestOptions,
        (upRes) => {
          const chunks: Buffer[] = [];
          upRes.on('data', (c) => chunks.push(c));
          upRes.on('end', () => {
            resolve({
              statusCode: upRes.statusCode!,
              headers: upRes.headers as Record<string, string>,
              body: Buffer.concat(chunks),
            });
          });
        },
      );

      upstream.on('error', reject);
      upstream.write(body);
      upstream.end();
    });
  }

  return new Promise((resolve, reject) => {
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', async () => {
        const body = Buffer.concat(chunks);
        const incomingHeaders = { ...(req.headers as Record<string, string>) };

        try {
          let result = await forwardRequest(body, incomingHeaders, req.method!, req.url!);

          // Auto-refresh on 401 in OAuth mode
          if (result.statusCode === 401 && authMode === 'oauth') {
            try {
              await ensureFreshToken();
              result = await forwardRequest(body, incomingHeaders, req.method!, req.url!);
            } catch (refreshErr) {
              logger.error({ err: refreshErr }, 'OAuth token refresh failed');
              // Fall through with original 401
            }
          }

          res.writeHead(result.statusCode, result.headers);
          res.end(result.body);
        } catch (err) {
          logger.error({ err, url: req.url }, 'Credential proxy upstream error');
          if (!res.headersSent) {
            res.writeHead(502);
            res.end('Bad Gateway');
          }
        }
      });
    });

    server.listen(port, host, () => {
      logger.info({ port, host, authMode }, 'Credential proxy started');
      resolve(server);
    });

    server.on('error', reject);
  });
}

/** Detect which auth mode the host is configured for. */
export function detectAuthMode(): AuthMode {
  const secrets = readEnvFile(['ANTHROPIC_API_KEY']);
  return secrets.ANTHROPIC_API_KEY ? 'api-key' : 'oauth';
}
