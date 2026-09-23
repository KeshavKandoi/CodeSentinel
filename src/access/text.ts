import { findMatching, stripJsComments } from '../routes/jsScanner.js';
import type { AdapterContext, AttackSurfaceEntry } from '../routes/types.js';

const JS_EXTS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'] as const;
const PY_EXTS = ['.py'] as const;
const JS_KEYWORDS = new Set(['if', 'for', 'while', 'switch', 'catch', 'function', 'return', 'constructor', 'with', 'else']);
const PY_DEF_RE = /^(\s*)(?:async\s+def|def|class)\s+([A-Za-z_]\w*)/;

export interface SourcePart {
  role: 'route' | 'handler';
  file: string;
  startLine: number;
  code: string;
  plain: string;
}

export interface RouteSource {
  python: boolean;
  parts: SourcePart[];
  handlerResolved: boolean;
}

export interface Definition {
  name: string;
  kind: 'function' | 'class';
  file: string;
  line: number;
  startLine: number;
  code: string;
}

export interface FileSource {
  file: string;
  python: boolean;
  code: string;
  plain: string;
}

export interface SourceResolver {
  forEntry(entry: AttackSurfaceEntry): RouteSource;
  findDefinition(name: string, preferFile?: string): Definition | null;
  fileSource(file: string): FileSource | null;
  sourceFiles(): string[];
}

export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function countChar(text: string, ch: string): number {
  let n = 0;
  for (const c of text) if (c === ch) n++;
  return n;
}

export function lineAtOffset(text: string, offset: number, startLine: number): number {
  let line = startLine;
  const end = Math.min(offset, text.length);
  for (let i = 0; i < end; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

function blankText(text: string): string {
  return text.replace(/[^\n]/g, ' ');
}

export function stripPythonComments(src: string): string {
  const out: string[] = [];
  const n = src.length;
  let i = 0;
  while (i < n) {
    const c = src.charAt(i);
    if (src.startsWith('"""', i) || src.startsWith("'''", i)) {
      const q = src.slice(i, i + 3);
      const close = src.indexOf(q, i + 3);
      const stop = close === -1 ? n : close + 3;
      out.push(src.slice(i, stop));
      i = stop;
    } else if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n && src.charAt(j) !== c && src.charAt(j) !== '\n') {
        if (src.charAt(j) === '\\') j++;
        j++;
      }
      const stop = Math.min(n, j + 1);
      out.push(src.slice(i, stop));
      i = stop;
    } else if (c === '#') {
      let j = i;
      while (j < n && src.charAt(j) !== '\n') j++;
      out.push(' '.repeat(j - i));
      i = j;
    } else {
      out.push(c);
      i++;
    }
  }
  return out.join('');
}

export function blankStrings(code: string, python: boolean): string {
  const out: string[] = [];
  const n = code.length;
  let i = 0;
  while (i < n) {
    const c = code.charAt(i);
    if (python && (code.startsWith('"""', i) || code.startsWith("'''", i))) {
      const q = code.slice(i, i + 3);
      const close = code.indexOf(q, i + 3);
      const stop = close === -1 ? n : close;
      out.push(q, blankText(code.slice(i + 3, stop)));
      if (close === -1) {
        i = n;
      } else {
        out.push(q);
        i = close + 3;
      }
      continue;
    }
    if (c === '"' || c === "'" || (!python && c === '`')) {
      const multiline = c === '`';
      let j = i + 1;
      while (j < n && code.charAt(j) !== c && (multiline || code.charAt(j) !== '\n')) {
        if (code.charAt(j) === '\\') j++;
        j++;
      }
      const stop = Math.min(j, n);
      out.push(c, blankText(code.slice(i + 1, stop)));
      if (stop < n && code.charAt(stop) === c) {
        out.push(c);
        i = stop + 1;
      } else {
        i = stop;
      }
      continue;
    }
    out.push(c);
    i++;
  }
  return out.join('');
}

export function normalizePlain(code: string, python: boolean): string {
  return blankStrings(code, python).replace(/\?\./g, '.').replace(/(\w)!\./g, '$1.');
}

function makePart(role: 'route' | 'handler', file: string, startLine: number, code: string, python: boolean): SourcePart {
  return { role, file, startLine, code, plain: normalizePlain(code, python) };
}

function lineStartsOf(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return starts;
}

function lineOfIndex(starts: readonly number[], index: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if ((starts[mid] ?? 0) <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

export function decoratorStart(lines: readonly string[], idx: number): number {
  let start = idx;
  let balance = 0;
  for (let k = idx - 1; k >= 0 && idx - k <= 40; k--) {
    const line = lines[k] ?? '';
    const trimmed = line.trim();
    if (trimmed === '') break;
    balance += countChar(line, ')') + countChar(line, ']') - countChar(line, '(') - countChar(line, '[');
    if (balance > 0 || trimmed.startsWith('@')) {
      start = k;
      continue;
    }
    break;
  }
  return start;
}

function signatureEnd(lines: readonly string[], defIdx: number): number {
  let depth = 0;
  for (let j = defIdx; j < lines.length && j < defIdx + 60; j++) {
    const line = lines[j] ?? '';
    depth += countChar(line, '(') + countChar(line, '[') - countChar(line, ')') - countChar(line, ']');
    if (depth <= 0) return j;
  }
  return defIdx;
}

function pythonBlockAt(lines: readonly string[], defIdx: number): { start: number; end: number } {
  const defLine = lines[defIdx] ?? '';
  const indent = defLine.length - defLine.trimStart().length;
  const start = decoratorStart(lines, defIdx);
  const sigEnd = signatureEnd(lines, defIdx);
  let end = sigEnd;
  for (let j = sigEnd + 1; j < lines.length; j++) {
    const line = lines[j] ?? '';
    if (line.trim() === '') continue;
    const lineIndent = line.length - line.trimStart().length;
    if (lineIndent <= indent) break;
    end = j;
  }
  return { start, end };
}

function pythonRouteBlock(lines: readonly string[], startIdx: number): { start: number; end: number } | null {
  const limit = Math.min(lines.length - 1, startIdx + 30);
  for (let j = startIdx; j <= limit; j++) {
    if (/^\s*(?:async\s+def|def)\s/.test(lines[j] ?? '')) return pythonBlockAt(lines, j);
  }
  return null;
}

function pythonDefinitions(file: string, code: string): Definition[] {
  const lines = code.split('\n');
  const out: Definition[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    const m = PY_DEF_RE.exec(line);
    if (!m) continue;
    const name = m[2] ?? '';
    if (name === '') continue;
    const block = pythonBlockAt(lines, i);
    out.push({
      name,
      kind: /^\s*class\s/.test(line) ? 'class' : 'function',
      file,
      line: i + 1,
      startLine: block.start + 1,
      code: lines.slice(block.start, block.end + 1).join('\n'),
    });
  }
  return out;
}

function jsDefinitions(file: string, code: string): Definition[] {
  const out: Definition[] = [];
  const starts = lineStartsOf(code);
  const push = (name: string, kind: 'function' | 'class', from: number, searchFrom: number): void => {
    const open = code.indexOf('{', searchFrom);
    const between = open === -1 ? '' : code.slice(searchFrom, open);
    let end: number;
    if (open === -1 || between.length > 300 || between.includes(';')) {
      const newline = code.indexOf('\n', searchFrom);
      end = newline === -1 ? code.length : newline;
    } else {
      const close = findMatching(code, open);
      end = close === -1 ? Math.min(code.length, open + 2000) : close + 1;
    }
    const line = lineOfIndex(starts, from);
    out.push({ name, kind, file, line, startLine: line, code: code.slice(from, end) });
  };
  const run = (base: RegExp, kind: 'function' | 'class', fromBrace: boolean): void => {
    const re = new RegExp(base.source, base.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(code)) !== null) {
      const name = m[1] ?? '';
      if (name === '' || JS_KEYWORDS.has(name)) continue;
      const end = m.index + m[0].length;
      push(name, kind, m.index, fromBrace ? end - 1 : end);
    }
  };
  run(/\b(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(/g, 'function', false);
  run(
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*(?::[^=\n{]+)?=>|[A-Za-z_$][\w$]*\s*=>)/g,
    'function',
    false
  );
  run(/\bclass\s+([A-Za-z_$][\w$]*)/g, 'class', false);
  run(/^[ \t]*(?:(?:public|private|protected|static|async|readonly)\s+)*([A-Za-z_$][\w$]*)\s*\([^)\n]*\)\s*(?::\s*[^{\n]+)?\{/gm, 'function', true);
  return out;
}

function blankRange(text: string, from: number, to: number): string {
  return text.slice(0, from) + blankText(text.slice(from, to)) + text.slice(to);
}

export function narrowByMethod(text: string, method: string): string {
  if (method === 'ALL' || method === 'unknown') return text;
  const re = /\b(?:req|request)\s*\.\s*method\s*(?:===|==)\s*['"]([A-Za-z]+)['"]\s*\)?\s*\{/g;
  const blocks: Array<{ method: string; from: number; to: number }> = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const open = m.index + m[0].length - 1;
    const close = findMatching(text, open);
    if (close === -1) continue;
    blocks.push({ method: (m[1] ?? '').toUpperCase(), from: m.index, to: close + 1 });
  }
  let out = text;
  for (const block of blocks) if (block.method !== method) out = blankRange(out, block.from, block.to);
  return out;
}

function handlerName(entry: AttackSurfaceEntry): string | null {
  const raw = entry.handler.trim();
  if (raw === '' || raw === 'unknown' || /^anonymous|^\(|=>|function\s*\(|^async\s*\(/.test(raw)) return null;
  const cleaned = raw.replace(/\.as_view\b[\s\S]*$/, '').replace(/\([\s\S]*$/, '');
  const last = cleaned.split('.').pop() ?? '';
  return /^[A-Za-z_$][\w$]*$/.test(last) ? last : null;
}

function functionEndLine(code: string, lines: readonly string[], startIdx: number): number {
  let offset = 0;
  for (let i = 0; i < startIdx; i++) offset += (lines[i] ?? '').length + 1;
  const open = code.indexOf('(', offset);
  if (open === -1 || open - offset > 300) return startIdx;
  const close = findMatching(code, open);
  if (close === -1) return startIdx;
  const inner = code.slice(open + 1, close);
  if (/=>|\bfunction\b/.test(inner)) return lineAtOffset(code, close, 0);
  const brace = code.indexOf('{', close);
  if (brace === -1 || brace - close > 200 || code.slice(close, brace).includes(';')) return startIdx;
  const end = findMatching(code, brace);
  return end === -1 ? startIdx : lineAtOffset(code, end, 0);
}

export function createSourceResolver(ctx: AdapterContext): SourceResolver {
  const stripped = new Map<string, { code: string; python: boolean } | null>();
  let index: Map<string, Definition[]> | null = null;

  const fileCode = (file: string): { code: string; python: boolean } | null => {
    if (stripped.has(file)) return stripped.get(file) ?? null;
    const src = ctx.readSource(file);
    const python = file.endsWith('.py');
    const value = src ? { code: python ? stripPythonComments(src.content) : stripJsComments(src.content), python } : null;
    stripped.set(file, value);
    return value;
  };

  const sourceFiles = (): string[] => [...ctx.listSourceFiles(JS_EXTS), ...ctx.listSourceFiles(PY_EXTS)];

  const buildIndex = (): Map<string, Definition[]> => {
    const map = new Map<string, Definition[]>();
    for (const file of sourceFiles()) {
      const fc = fileCode(file);
      if (!fc) continue;
      const found = fc.python ? pythonDefinitions(file, fc.code) : jsDefinitions(file, fc.code);
      for (const def of found) {
        const list = map.get(def.name) ?? [];
        list.push(def);
        map.set(def.name, list);
      }
    }
    return map;
  };

  const findDefinition = (name: string, preferFile?: string): Definition | null => {
    if (index === null) index = buildIndex();
    const list = index.get(name);
    if (!list || list.length === 0) return null;
    if (preferFile) {
      const same = list.find((d) => d.file === preferFile);
      if (same) return same;
    }
    return list.length === 1 ? (list[0] ?? null) : null;
  };

  return {
    sourceFiles,
    findDefinition,
    fileSource(file) {
      const fc = fileCode(file);
      if (!fc) return null;
      return { file, python: fc.python, code: fc.code, plain: normalizePlain(fc.code, fc.python) };
    },
    forEntry(entry) {
      const file = entry.file;
      const fc = fileCode(file);
      const python = entry.language === 'python';
      const parts: SourcePart[] = [];
      let routeFrom = 0;
      let routeTo = 0;
      if (fc) {
        const lines = fc.code.split('\n');
        const startIdx = Math.min(Math.max(0, entry.sourceRange.startLine - 1), Math.max(0, lines.length - 1));
        const endIdx = Math.min(lines.length - 1, Math.max(startIdx, entry.sourceRange.endLine - 1));
        const block = python && entry.framework === 'fastapi' ? pythonRouteBlock(lines, startIdx) : null;
        if (block) {
          routeFrom = block.start;
          routeTo = block.end;
          parts.push(makePart('route', file, block.start + 1, lines.slice(block.start, block.end + 1).join('\n'), true));
        } else {
          routeFrom = entry.framework === 'nestjs' ? decoratorStart(lines, startIdx) : startIdx;
          routeTo = entry.framework === 'nextjs' ? Math.max(endIdx, functionEndLine(fc.code, lines, startIdx)) : endIdx;
          let text = lines.slice(routeFrom, routeTo + 1).join('\n');
          if (entry.framework === 'nextjs' && /(^|\/)pages\/api\//.test(file)) text = narrowByMethod(text, entry.method);
          parts.push(makePart('route', file, routeFrom + 1, text, python));
        }
      }
      let handlerResolved = false;
      const name = entry.framework === 'nestjs' || entry.framework === 'nextjs' ? null : handlerName(entry);
      if (name) {
        const def = findDefinition(name, file);
        const inside = def !== null && def.file === file && def.line >= routeFrom + 1 && def.line <= routeTo + 1;
        if (def && !inside) {
          parts.push(makePart('handler', def.file, def.startLine, def.code, def.file.endsWith('.py')));
          handlerResolved = true;
        }
      }
      return { python, parts, handlerResolved };
    },
  };
}
