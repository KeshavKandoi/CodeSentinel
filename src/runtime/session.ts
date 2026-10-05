import type { TestSession } from './types.js';


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
