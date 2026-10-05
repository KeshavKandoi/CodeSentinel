
import { redactSecurityText } from '../security/utils.js';

export interface CallArg {
  text: string;
  start: number;
}

export function stripJsComments(src: string): string {
  let out = '';
  let i = 0;
  const n = src.length;
  let mode: 'code' | 'sq' | 'dq' | 'tpl' = 'code';
  while (i < n) {
    const c = src.charAt(i);
    const d = src.charAt(i + 1);
    if (mode === 'code') {
      if (c === '/' && d === '/') {
        while (i < n && src.charAt(i) !== '\n') {
          out += ' ';
          i++;
        }
        continue;
      }
      if (c === '/' && d === '*') {
        out += '  ';
        i += 2;
        while (i < n && !(src.charAt(i) === '*' && src.charAt(i + 1) === '/')) {
          out += src.charAt(i) === '\n' ? '\n' : ' ';
          i++;
        }
        if (i < n) {
          out += '  ';
          i += 2;
        }
        continue;
      }
      if (c === "'") mode = 'sq';
      else if (c === '"') mode = 'dq';
      else if (c === '`') mode = 'tpl';
      out += c;
      i++;
      continue;
    }
    if (c === '\\') {
      out += c + d;
      i += 2;
      continue;
    }
    if (mode === 'tpl') {
      if (c === '`') mode = 'code';
    } else if (c === '\n') {
      mode = 'code';
    } else if ((mode === 'sq' && c === "'") || (mode === 'dq' && c === '"')) {
      mode = 'code';
    }
    out += c;
    i++;
  }
  return out;
}

export function blankStringContents(src: string): string {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src.charAt(i);
    if (c !== '"' && c !== "'" && c !== '`') {
      out += c;
      i++;
      continue;
    }
    out += c;
    let j = i + 1;
    while (j < n) {
      const d = src.charAt(j);
      if (d === '\\') {
        out += ' ';
        if (j + 1 < n) out += src.charAt(j + 1) === '\n' ? '\n' : ' ';
        j += 2;
        continue;
      }
      if (d === c || (d === '\n' && c !== '`')) break;
      out += d === '\n' ? '\n' : ' ';
      j++;
    }
    if (j < n && src.charAt(j) === c) {
      out += c;
      j++;
    }
    i = j;
  }
  return out;
}

export function buildLineIndex(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) starts.push(i + 1);
  }
  return starts;
}

export function lineAtIndex(starts: readonly number[], index: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if ((starts[mid] ?? 0) <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

function skipString(text: string, start: number): number {
  const quote = text.charAt(start);
  let i = start + 1;
  while (i < text.length) {
    const c = text.charAt(i);
    if (c === '\\') {
      i += 2;
      continue;
    }
    if (c === quote) return i + 1;
    if (c === '\n' && quote !== '`') return i;
    i++;
  }
  return text.length;
}

export function findMatching(text: string, openIdx: number, limit = 200_000): number {
  const open = text.charAt(openIdx);
  const close = open === '(' ? ')' : open === '[' ? ']' : open === '{' ? '}' : '';
  if (close === '') return -1;
  let depth = 0;
  const end = Math.min(text.length, openIdx + limit);
  for (let i = openIdx; i < end; i++) {
    const c = text.charAt(i);
    if (c === '"' || c === "'" || c === '`') {
      i = skipString(text, i) - 1;
      continue;
    }
    if (c === open) depth++;
    else if (c === close) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

export function readCallArgs(text: string, openIdx: number): { args: CallArg[]; endIdx: number } | null {
  if (text.charAt(openIdx) !== '(') return null;
  const args: CallArg[] = [];
  const limit = Math.min(text.length, openIdx + 200_000);
  let depth = 0;
  let argStart = openIdx + 1;
  const pushArg = (end: number): void => {
    const raw = text.slice(argStart, end);
    const trimmed = raw.trim();
    if (trimmed.length > 0) args.push({ text: trimmed, start: argStart + (raw.length - raw.trimStart().length) });
  };
  for (let i = openIdx; i < limit; i++) {
    const c = text.charAt(i);
    if (c === '"' || c === "'" || c === '`') {
      i = skipString(text, i) - 1;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) {
        pushArg(i);
        return { args, endIdx: i };
      }
      if (depth < 0) return null;
    } else if (c === ',' && depth === 1) {
      pushArg(i);
      argStart = i + 1;
    }
  }
  return null;
}

export function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 3)}...` : text;
}

const FUNCTION_LIKE_RE = /^(async\s*)?(function\b|\(|[\w$]+\s*=>)/;

export function isFunctionLike(text: string): boolean {
  return FUNCTION_LIKE_RE.test(text.trim());
}

export function argDisplayName(text: string): string {
  const t = text.trim().replace(/\s+/g, ' ');
  if (isFunctionLike(t)) return '<inline function>';
  const quoted = t.replace(/(:\s*)(['"`])(?:\\.|(?!\2)[^\\\n])*\2/g, '$1$2[REDACTED]$2');
  return truncate(redactSecurityText(quoted), 80);
}

export function splitArrayItems(text: string): string[] {
  const t = text.trim();
  if (!t.startsWith('[') || !t.endsWith(']')) return [t];
  const parsed = readCallArgs(`(${t.slice(1, -1)})`, 0);
  return parsed ? parsed.args.map((a) => a.text) : [t];
}

export function flattenArgNames(args: readonly CallArg[]): string[] {
  const names: string[] = [];
  for (const arg of args) {
    for (const item of splitArrayItems(arg.text)) names.push(argDisplayName(item));
  }
  return names;
}

export function describeHandler(text: string): { handler: string; controller: string } {
  const name = argDisplayName(text);
  if (name === '<inline function>') return { handler: name, controller: 'unknown' };
  const m = /^([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$.]*)$/.exec(name);
  return { handler: name === '' ? 'unknown' : name, controller: m?.[1] ?? 'unknown' };
}

export function stringLiteralValue(text: string): string | null {
  const m = /^(['"`])((?:\\.|(?!\1)[^\\])*)\1$/.exec(text.trim());
  if (!m) return null;
  const value = m[2] ?? '';
  if (m[1] === '`' && value.includes('${')) return null;
  return value;
}

export function collectConstStrings(code: string): Map<string, string> {
  const out = new Map<string, string>();
  const re = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*string)?\s*=\s*(['"])((?:(?!\2)[^\\\n])*)\2/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const name = m[1];
    const value = m[3];
    if (name !== undefined && value !== undefined) out.set(name, value);
  }
  return out;
}

export function evalPathString(text: string, consts: ReadonlyMap<string, string>): string | null {
  const t = text.trim();
  const lit = stringLiteralValue(t);
  if (lit !== null) return lit;
  if (/^[A-Za-z_$][\w$]*$/.test(t)) return consts.get(t) ?? null;
  if (t.startsWith('`') && t.endsWith('`')) {
    let unresolved = false;
    const value = t.slice(1, -1).replace(/\$\{\s*([A-Za-z_$][\w$]*)\s*\}/g, (_match: string, name: string) => {
      const known = consts.get(name);
      if (known === undefined) {
        unresolved = true;
        return '';
      }
      return known;
    });
    return unresolved || value.includes('${') ? null : value;
  }
  return null;
}

export function evalPathList(text: string, consts: ReadonlyMap<string, string>): string[] | null {
  const t = text.trim();
  if (t.startsWith('[') && t.endsWith(']')) {
    const inner = t.slice(1, -1);
    const litRe = /(['"`])((?:\\.|(?!\1)[^\\])*)\1/g;
    const values: string[] = [];
    let m: RegExpExecArray | null;
    while ((m = litRe.exec(inner)) !== null) values.push(m[2] ?? '');
    const rest = inner.replace(/(['"`])((?:\\.|(?!\1)[^\\])*)\1/g, '').replace(/[\s,]/g, '');
    return rest === '' && values.length > 0 ? values : null;
  }
  const single = evalPathString(t, consts);
  return single === null ? null : [single];
}

const PATH_IDENT_RE = /^(?:[A-Z][A-Z0-9_]*|[A-Za-z_$][\w$]*(?:Prefix|PREFIX|BasePath|BaseUrl))$/;

export function isPathLike(text: string, consts: ReadonlyMap<string, string>): boolean {
  const t = text.trim();
  if (t.startsWith('[')) return evalPathList(t, consts) !== null;
  if (/^['"`]/.test(t)) return true;
  if (consts.has(t)) return true;
  return PATH_IDENT_RE.test(t);
}

export function findFunctionBody(code: string, name: string): string | null {
  const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const decl = new RegExp(
    `(?:function\\s+${esc}\\s*\\(|(?:const|let|var)\\s+${esc}\\b[^=;]*=\\s*(?:async\\s*)?(?:function\\b|\\(|[\\w$]+\\s*=>))`
  ).exec(code);
  if (!decl) return null;
  const tail = code.slice(decl.index, decl.index + 40_000);
  const bodyStart = /(?:\)[^{;]*|=>\s*)\{/.exec(tail);
  if (!bodyStart || bodyStart.index > 300) return null;
  const openIdx = decl.index + bodyStart.index + bodyStart[0].length - 1;
  const close = findMatching(code, openIdx);
  return close === -1 ? null : code.slice(openIdx, close + 1);
}

export interface RequestUsage {
  params: string[];
  query: string[];
  body: string[];
  headers: string[];
  bodyWhole: boolean;
  queryWhole: boolean;
}

export function extractRequestUsage(code: string): RequestUsage {
  const sets = {
    params: new Set<string>(),
    query: new Set<string>(),
    body: new Set<string>(),
    headers: new Set<string>(),
  };
  type Key = keyof typeof sets;
  let m: RegExpExecArray | null;

  const dotRe = /\breq(?:uest)?\s*\.\s*(params|query|body|headers)\s*\.\s*([A-Za-z_$][\w$]*)/g;
  while ((m = dotRe.exec(code)) !== null) sets[m[1] as Key].add(m[2] ?? '');

  const bracketRe = /\breq(?:uest)?\s*\.\s*(params|query|body|headers)\s*\[\s*['"]([^'"]+)['"]\s*\]/g;
  while ((m = bracketRe.exec(code)) !== null) sets[m[1] as Key].add(m[2] ?? '');

  const destructRe = /(?:const|let|var)\s*\{([^}]*)\}\s*=\s*req(?:uest)?\s*\.\s*(params|query|body|headers)\b/g;
  while ((m = destructRe.exec(code)) !== null) {
    for (const part of (m[1] ?? '').split(',')) {
      const name = (part.split(/[:=]/)[0] ?? '').trim();
      if (/^[A-Za-z_$][\w$]*$/.test(name)) sets[m[2] as Key].add(name);
    }
  }

  const list = (s: Set<string>): string[] => Array.from(s).filter((x) => x !== '').sort();
  return {
    params: list(sets.params),
    query: list(sets.query),
    body: list(sets.body),
    headers: list(sets.headers),
    bodyWhole: /\breq(?:uest)?\s*\.\s*body\b/.test(code),
    queryWhole: /\breq(?:uest)?\s*\.\s*query\b/.test(code),
  };
}

export function extractResponseIndicators(code: string): string[] {
  const out = new Set<string>();
  let m: RegExpExecArray | null;
  const methodRe = /\bres\s*\.\s*(json|send|render|redirect|sendFile|download|end|sendStatus)\s*\(/g;
  while ((m = methodRe.exec(code)) !== null) out.add(`res.${m[1] ?? ''}`);
  const statusRe = /\bres\s*\.\s*status\s*\(\s*(\d{3})\s*\)/g;
  while ((m = statusRe.exec(code)) !== null) out.add(`status:${m[1] ?? ''}`);
  return Array.from(out);
}
