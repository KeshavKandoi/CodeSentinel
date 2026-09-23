import { findMatching, readCallArgs } from './jsScanner.js';

/** Top-level properties of an object literal `{ a: 1, b, c() {} }` as key -> value text. Spreads are skipped. */
export function parseObjectProps(objText: string): Map<string, string> {
  const out = new Map<string, string>();
  const t = objText.trim();
  if (!t.startsWith('{') || !t.endsWith('}')) return out;
  const parsed = readCallArgs(`(${t.slice(1, -1)})`, 0);
  if (!parsed) return out;
  for (const arg of parsed.args) {
    const m = /^(?:async\s+)?(['"]?)([\w$-]+)\1\s*(:)?\s*/.exec(arg.text);
    if (!m) continue;
    const key = m[2] ?? '';
    const rest = arg.text.slice(m[0].length);
    if (m[3]) out.set(key, rest);
    else if (rest === '') out.set(key, key);
    else out.set(key, `function ${rest}`);
  }
  return out;
}

/** Text of `const NAME = { ... }` declared in the same file, or null. */
export function findObjectConst(code: string, name: string): string | null {
  const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const m = new RegExp(`(?:const|let|var)\\s+${esc}\\s*(?::[^=\\n]+)?=\\s*\\{`).exec(code);
  if (!m) return null;
  const openIdx = m.index + m[0].length - 1;
  const close = findMatching(code, openIdx);
  return close === -1 ? null : code.slice(openIdx, close + 1);
}
