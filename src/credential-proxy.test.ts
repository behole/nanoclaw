import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import http from 'http';
import type { AddressInfo } from 'net';
import fs from 'fs';
import path from 'path';
import os from 'os';

const mockEnv: Record<string, string> = {};
vi.mock('./env.js', () => ({
  readEnvFile: vi.fn(() => ({ ...mockEnv })),
}));

vi.mock('./logger.js', () => ({
  logger: { info: vi.fn(), error: vi.fn(), debug: vi.fn(), warn: vi.fn() },
}));

import { startCredentialProxy } from './credential-proxy.js';

function makeRequest(
  port: number,
  options: http.RequestOptions,
  body = '',
): Promise<{
  statusCode: number;
  body: string;
  headers: http.IncomingHttpHeaders;
}> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { ...options, hostname: '127.0.0.1', port },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode!,
            body: Buffer.concat(chunks).toString(),
            headers: res.headers,
          });
        });
      },
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

describe('credential-proxy', () => {
  let proxyServer: http.Server;
  let upstreamServer: http.Server;
  let proxyPort: number;
  let upstreamPort: number;
  let lastUpstreamHeaders: http.IncomingHttpHeaders;

  beforeEach(async () => {
    lastUpstreamHeaders = {};

    upstreamServer = http.createServer((req, res) => {
      lastUpstreamHeaders = { ...req.headers };
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });
    await new Promise<void>((resolve) =>
      upstreamServer.listen(0, '127.0.0.1', resolve),
    );
    upstreamPort = (upstreamServer.address() as AddressInfo).port;
  });

  afterEach(async () => {
    await new Promise<void>((r) => proxyServer?.close(() => r()));
    await new Promise<void>((r) => upstreamServer?.close(() => r()));
    for (const key of Object.keys(mockEnv)) delete mockEnv[key];
  });

  async function startProxy(env: Record<string, string>): Promise<number> {
    Object.assign(mockEnv, env, {
      ANTHROPIC_BASE_URL: `http://127.0.0.1:${upstreamPort}`,
    });
    proxyServer = await startCredentialProxy(0);
    return (proxyServer.address() as AddressInfo).port;
  }

  it('API-key mode injects x-api-key and strips placeholder', async () => {
    proxyPort = await startProxy({ ANTHROPIC_API_KEY: 'sk-ant-real-key' });

    await makeRequest(
      proxyPort,
      {
        method: 'POST',
        path: '/v1/messages',
        headers: {
          'content-type': 'application/json',
          'x-api-key': 'placeholder',
        },
      },
      '{}',
    );

    expect(lastUpstreamHeaders['x-api-key']).toBe('sk-ant-real-key');
  });

  it('OAuth mode replaces Authorization when container sends one', async () => {
    proxyPort = await startProxy({
      CLAUDE_CODE_OAUTH_TOKEN: 'real-oauth-token',
    });

    await makeRequest(
      proxyPort,
      {
        method: 'POST',
        path: '/api/oauth/claude_cli/create_api_key',
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer placeholder',
        },
      },
      '{}',
    );

    expect(lastUpstreamHeaders['authorization']).toBe(
      'Bearer real-oauth-token',
    );
  });

  it('OAuth mode does not inject Authorization when container omits it', async () => {
    proxyPort = await startProxy({
      CLAUDE_CODE_OAUTH_TOKEN: 'real-oauth-token',
    });

    // Post-exchange: container uses x-api-key only, no Authorization header
    await makeRequest(
      proxyPort,
      {
        method: 'POST',
        path: '/v1/messages',
        headers: {
          'content-type': 'application/json',
          'x-api-key': 'temp-key-from-exchange',
        },
      },
      '{}',
    );

    expect(lastUpstreamHeaders['x-api-key']).toBe('temp-key-from-exchange');
    expect(lastUpstreamHeaders['authorization']).toBeUndefined();
  });

  it('strips hop-by-hop headers', async () => {
    proxyPort = await startProxy({ ANTHROPIC_API_KEY: 'sk-ant-real-key' });

    await makeRequest(
      proxyPort,
      {
        method: 'POST',
        path: '/v1/messages',
        headers: {
          'content-type': 'application/json',
          connection: 'keep-alive',
          'keep-alive': 'timeout=5',
          'transfer-encoding': 'chunked',
        },
      },
      '{}',
    );

    // Proxy strips client hop-by-hop headers. Node's HTTP client may re-add
    // its own Connection header (standard HTTP/1.1 behavior), but the client's
    // custom keep-alive and transfer-encoding must not be forwarded.
    expect(lastUpstreamHeaders['keep-alive']).toBeUndefined();
    expect(lastUpstreamHeaders['transfer-encoding']).toBeUndefined();
  });

  describe('OAuth token auto-refresh', () => {
    let refreshServer: http.Server;
    let refreshPort: number;
    let upstreamRequestCount: number;
    let credentialsPath: string;
    let tmpDir: string;

    beforeEach(async () => {
      upstreamRequestCount = 0;
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-proxy-test-'));
      credentialsPath = path.join(tmpDir, '.credentials.json');
    });

    afterEach(async () => {
      await new Promise<void>((r) => refreshServer?.close(() => r()));
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('refreshes expired OAuth token on 401 and retries', async () => {
      // Upstream returns 401 on first request, 200 on retry (with new token)
      await new Promise<void>((r) => upstreamServer.close(() => r()));
      upstreamServer = http.createServer((req, res) => {
        upstreamRequestCount++;
        lastUpstreamHeaders = { ...req.headers };
        if (upstreamRequestCount === 1) {
          res.writeHead(401, { 'content-type': 'application/json' });
          res.end(JSON.stringify({
            type: 'error',
            error: { type: 'authentication_error', message: 'OAuth token has expired' },
          }));
        } else {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
        }
      });
      await new Promise<void>((resolve) =>
        upstreamServer.listen(upstreamPort, '127.0.0.1', resolve),
      );

      // Fake refresh endpoint returns new tokens
      refreshServer = http.createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => {
          const body = JSON.parse(Buffer.concat(chunks).toString());
          expect(body.grant_type).toBe('refresh_token');
          expect(body.refresh_token).toBe('old-refresh-token');
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({
            accessToken: 'new-access-token',
            refreshToken: 'new-refresh-token',
            expiresAt: Date.now() + 86400000,
          }));
        });
      });
      await new Promise<void>((resolve) =>
        refreshServer.listen(0, '127.0.0.1', resolve),
      );
      refreshPort = (refreshServer.address() as AddressInfo).port;

      // Write initial credentials file
      fs.writeFileSync(credentialsPath, JSON.stringify({
        claudeAiOauth: {
          accessToken: 'expired-token',
          refreshToken: 'old-refresh-token',
          expiresAt: Date.now() - 1000,
        },
      }));

      proxyPort = await startProxy({
        CLAUDE_CODE_OAUTH_TOKEN: 'expired-token',
        OAUTH_CREDENTIALS_PATH: credentialsPath,
        OAUTH_ENV_FILE_PATH: path.join(tmpDir, '.env'),
        OAUTH_REFRESH_URL: `http://127.0.0.1:${refreshPort}/v1/oauth/token`,
      });

      const res = await makeRequest(
        proxyPort,
        {
          method: 'POST',
          path: '/api/oauth/claude_cli/create_api_key',
          headers: {
            'content-type': 'application/json',
            authorization: 'Bearer placeholder',
          },
        },
        '{}',
      );

      expect(res.statusCode).toBe(200);
      expect(upstreamRequestCount).toBe(2);
      // Retry should use the new token
      expect(lastUpstreamHeaders['authorization']).toBe('Bearer new-access-token');

      // Credentials file should be updated
      const updated = JSON.parse(fs.readFileSync(credentialsPath, 'utf-8'));
      expect(updated.claudeAiOauth.accessToken).toBe('new-access-token');
      expect(updated.claudeAiOauth.refreshToken).toBe('new-refresh-token');
    });

    it('does not refresh on 401 in API-key mode', async () => {
      await new Promise<void>((r) => upstreamServer.close(() => r()));
      upstreamServer = http.createServer((req, res) => {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { type: 'authentication_error' } }));
      });
      await new Promise<void>((resolve) =>
        upstreamServer.listen(upstreamPort, '127.0.0.1', resolve),
      );

      proxyPort = await startProxy({ ANTHROPIC_API_KEY: 'sk-ant-bad-key' });

      const res = await makeRequest(
        proxyPort,
        {
          method: 'POST',
          path: '/v1/messages',
          headers: { 'content-type': 'application/json', 'x-api-key': 'placeholder' },
        },
        '{}',
      );

      // Should pass through the 401, not attempt refresh
      expect(res.statusCode).toBe(401);
    });

    it('concurrent 401s only trigger one refresh', async () => {
      let refreshCount = 0;
      await new Promise<void>((r) => upstreamServer.close(() => r()));
      upstreamServer = http.createServer((req, res) => {
        upstreamRequestCount++;
        lastUpstreamHeaders = { ...req.headers };
        // First 3 requests get 401, then 200
        if (upstreamRequestCount <= 3) {
          res.writeHead(401, { 'content-type': 'application/json' });
          res.end(JSON.stringify({
            type: 'error',
            error: { type: 'authentication_error', message: 'OAuth token has expired' },
          }));
        } else {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
        }
      });
      await new Promise<void>((resolve) =>
        upstreamServer.listen(upstreamPort, '127.0.0.1', resolve),
      );

      refreshServer = http.createServer((req, res) => {
        refreshCount++;
        const chunks: Buffer[] = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({
            accessToken: 'new-access-token',
            refreshToken: 'new-refresh-token',
            expiresAt: Date.now() + 86400000,
          }));
        });
      });
      await new Promise<void>((resolve) =>
        refreshServer.listen(0, '127.0.0.1', resolve),
      );
      refreshPort = (refreshServer.address() as AddressInfo).port;

      fs.writeFileSync(credentialsPath, JSON.stringify({
        claudeAiOauth: {
          accessToken: 'expired-token',
          refreshToken: 'old-refresh-token',
          expiresAt: Date.now() - 1000,
        },
      }));

      proxyPort = await startProxy({
        CLAUDE_CODE_OAUTH_TOKEN: 'expired-token',
        OAUTH_CREDENTIALS_PATH: credentialsPath,
        OAUTH_ENV_FILE_PATH: path.join(tmpDir, '.env'),
        OAUTH_REFRESH_URL: `http://127.0.0.1:${refreshPort}/v1/oauth/token`,
      });

      // Fire 3 concurrent requests
      const requests = Array.from({ length: 3 }, () =>
        makeRequest(
          proxyPort,
          {
            method: 'POST',
            path: '/api/oauth/claude_cli/create_api_key',
            headers: {
              'content-type': 'application/json',
              authorization: 'Bearer placeholder',
            },
          },
          '{}',
        ),
      );

      const results = await Promise.all(requests);
      // All should eventually succeed
      expect(results.every((r) => r.statusCode === 200)).toBe(true);
      // Only one refresh call should have been made
      expect(refreshCount).toBe(1);
    });
  });

  it('returns 502 when upstream is unreachable', async () => {
    Object.assign(mockEnv, {
      ANTHROPIC_API_KEY: 'sk-ant-real-key',
      ANTHROPIC_BASE_URL: 'http://127.0.0.1:59999',
    });
    proxyServer = await startCredentialProxy(0);
    proxyPort = (proxyServer.address() as AddressInfo).port;

    const res = await makeRequest(
      proxyPort,
      {
        method: 'POST',
        path: '/v1/messages',
        headers: { 'content-type': 'application/json' },
      },
      '{}',
    );

    expect(res.statusCode).toBe(502);
    expect(res.body).toBe('Bad Gateway');
  });
});
