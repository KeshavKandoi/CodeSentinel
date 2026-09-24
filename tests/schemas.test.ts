import { describe, it, expect } from 'vitest';
import {
  listFilesSchema,
  readFileSchema,
  searchFilesSchema,
  getProjectInfoSchema,
  runCommandSchema,
  dispatchSecurityActionSchema,
  safeValidate,
} from '../src/validation/schemas.js';

describe('listFilesSchema', () => {
  it('applies defaults for an empty object', () => {
    const result = safeValidate(listFilesSchema, {});
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.path).toBe('.');
    expect(result.data.recursive).toBe(false);
    expect(result.data.maxResults).toBe(1000);
  });

  it('accepts valid explicit input', () => {
    const result = safeValidate(listFilesSchema, { path: 'src', recursive: true, maxResults: 50 });
    expect(result.ok).toBe(true);
  });

  it('rejects unknown keys (strict mode)', () => {
    const result = safeValidate(listFilesSchema, { path: '.', evilKey: 'rm -rf /' });
    expect(result.ok).toBe(false);
  });

  it('rejects wrong types', () => {
    const result = safeValidate(listFilesSchema, { path: 123 });
    expect(result.ok).toBe(false);
  });

  it('rejects maxResults over the cap', () => {
    const result = safeValidate(listFilesSchema, { maxResults: 999_999 });
    expect(result.ok).toBe(false);
  });

  it('rejects null-byte paths', () => {
    const result = safeValidate(listFilesSchema, { path: 'src\0evil' });
    expect(result.ok).toBe(false);
  });
});

describe('readFileSchema', () => {
  it('requires path', () => {
    const result = safeValidate(readFileSchema, {});
    expect(result.ok).toBe(false);
  });

  it('accepts a valid path with optional maxBytes', () => {
    const result = safeValidate(readFileSchema, { path: 'README.md', maxBytes: 1000 });
    expect(result.ok).toBe(true);
  });

  it('rejects an empty path string', () => {
    const result = safeValidate(readFileSchema, { path: '' });
    expect(result.ok).toBe(false);
  });

  it('rejects negative maxBytes', () => {
    const result = safeValidate(readFileSchema, { path: 'a.txt', maxBytes: -1 });
    expect(result.ok).toBe(false);
  });
});

describe('searchFilesSchema', () => {
  it('requires query', () => {
    const result = safeValidate(searchFilesSchema, { path: '.' });
    expect(result.ok).toBe(false);
  });

  it('applies defaults', () => {
    const result = safeValidate(searchFilesSchema, { query: 'foo' });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.path).toBe('.');
    expect(result.data.caseSensitive).toBe(false);
    expect(result.data.isRegex).toBe(false);
    expect(result.data.maxResults).toBe(500);
  });

  it('rejects an empty query string', () => {
    const result = safeValidate(searchFilesSchema, { query: '' });
    expect(result.ok).toBe(false);
  });
});

describe('getProjectInfoSchema', () => {
  it('accepts an empty object', () => {
    const result = safeValidate(getProjectInfoSchema, {});
    expect(result.ok).toBe(true);
  });

  it('rejects unexpected keys', () => {
    const result = safeValidate(getProjectInfoSchema, { foo: 'bar' });
    expect(result.ok).toBe(false);
  });
});

describe('runCommandSchema', () => {
  it('requires command', () => {
    const result = safeValidate(runCommandSchema, { args: [] });
    expect(result.ok).toBe(false);
  });

  it('defaults args to an empty array', () => {
    const result = safeValidate(runCommandSchema, { command: 'ls' });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.args).toEqual([]);
  });

  it('rejects non-string array items in args', () => {
    const result = safeValidate(runCommandSchema, { command: 'ls', args: [1, 2, 3] });
    expect(result.ok).toBe(false);
  });

  it('rejects an empty command string', () => {
    const result = safeValidate(runCommandSchema, { command: '' });
    expect(result.ok).toBe(false);
  });

  it('rejects malformed / non-object input entirely', () => {
    const result = safeValidate(runCommandSchema, 'just a string, not an object');
    expect(result.ok).toBe(false);
  });

  it('rejects null input', () => {
    const result = safeValidate(runCommandSchema, null);
    expect(result.ok).toBe(false);
  });

  it('rejects too many args (over the cap)', () => {
    const result = safeValidate(runCommandSchema, { command: 'ls', args: new Array(1000).fill('x') });
    expect(result.ok).toBe(false);
  });
});

describe('bounded external-agent inputs', () => {
  it('rejects oversized orchestration arguments', () => {
    const result = safeValidate(dispatchSecurityActionSchema, {
      investigationId: 'audit-1',
      action: 'get_security_audit_state',
      arguments: { oversized: 'x'.repeat(20_000) },
    });
    expect(result.ok).toBe(false);
  });

  it('rejects excessive or CRLF-injected runtime session headers', async () => {
    const { runtimeVerificationRequestSchema } = await import('../src/validation/schemas.js');
    const result = safeValidate(runtimeVerificationRequestSchema, {
      findingId: 'finding-1',
      target: { allowedOrigin: 'http://127.0.0.1:3000' },
      sessions: [{ id: 'user', kind: 'authenticated', headers: { Authorization: 'Bearer ok\r\nX-Injected: yes' } }],
    });
    expect(result.ok).toBe(false);
  });
});
