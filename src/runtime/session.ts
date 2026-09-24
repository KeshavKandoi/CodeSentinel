import type { TestSession } from './types.js';

/**
 * Test-session configuration. Credentials come only from what the caller
 * explicitly passes into verify_finding (itself populated only from
 * environment variables or other explicit runtime configuration the
 * operator controls) -- this module never reads .env files or any other
 * project source automatically. It only validates and indexes what it is
 * given, and always provides an implicit "anonymous" unauthenticated
 * session so every case can test the unauthenticated path even if the
 * caller supplied none.
 */

export function buildSessionMap(sessions: readonly TestSession[]): Map<string, TestSession> {
  const map = new Map<string, TestSession>();
  for (const s of sessions) {
    if (!s.id || typeof s.id !== 'string') continue;
    map.set(s.id, s);
  }
  if (!map.has('anonymous')) {
    map.set('anonymous', { id: 'anonymous', kind: 'unauthenticated' });
  }
  return map;
}

export function hasSession(sessions: Map<string, TestSession>, id: string): boolean {
  return sessions.has(id);
}

export function missingSessions(sessions: Map<string, TestSession>, required: readonly string[]): string[] {
  return required.filter((id) => !sessions.has(id));
}
