import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it } from 'node:test';

const repoRoot = resolve(import.meta.dirname, '..');
const vercelConfig = JSON.parse(readFileSync(resolve(repoRoot, 'vercel.json'), 'utf8'));

function catchAllHeaders() {
  const route = vercelConfig.headers?.find(({ source }) => source === '/(.*)');
  assert.ok(route, 'vercel.json must define response headers for every route');
  return new Map(route.headers.map(({ key, value }) => [key.toLowerCase(), value]));
}

describe('Vercel security headers', () => {
  it('applies browser hardening headers to every website and docs route', () => {
    const headers = catchAllHeaders();

    assert.equal(headers.get('x-content-type-options'), 'nosniff');
    assert.equal(headers.get('x-frame-options'), 'DENY');
    assert.equal(headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
    assert.equal(
      headers.get('permissions-policy'),
      'camera=(), geolocation=(), microphone=(), payment=(), usb=()',
    );
  });

  it('enforces a restrictive content security policy', () => {
    const csp = catchAllHeaders().get('content-security-policy');
    assert.ok(csp, 'Content-Security-Policy header is required');

    for (const directive of [
      "default-src 'self'",
      "base-uri 'self'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
      "script-src 'self' 'unsafe-inline'",
      "connect-src 'self'",
      "font-src 'self' data:",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https://api.star-history.com https://github.com https://goreportcard.com https://img.shields.io https://pkg.go.dev",
    ]) {
      assert.match(csp, new RegExp(`(?:^|; )${directive.replaceAll(/[.*+?^${}()|[\\]\\\\]/g, '\\$&')}(?:;|$)`));
    }

    assert.doesNotMatch(csp, /'unsafe-eval'/);
    assert.doesNotMatch(csp, /https?:[^;]*script-src|script-src[^;]*https?:/);
  });
});
