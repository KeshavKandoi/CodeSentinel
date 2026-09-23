import path from 'node:path';

export interface ImportBinding {
  spec: string;
  imported: string; // 'default', '*', or a named export
}

export interface ModuleExports {
  defaultVar?: string;
  named: Map<string, string>;
}

const RESOLVE_EXTS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'] as const;

function addImportClause(out: Map<string, ImportBinding>, clauseRaw: string, spec: string): void {
  const clause = clauseRaw.trim().replace(/^type\s+/, '');
  const braceIdx = clause.indexOf('{');
  const head = (braceIdx >= 0 ? clause.slice(0, braceIdx) : clause).replace(/,\s*$/, '').trim();
  if (head.startsWith('* as ')) out.set(head.slice(5).trim(), { spec, imported: '*' });
  else if (head.length > 0) out.set(head, { spec, imported: 'default' });
  if (braceIdx >= 0) {
    const close = clause.indexOf('}', braceIdx);
    const inner = clause.slice(braceIdx + 1, close >= 0 ? close : undefined);
    for (const partRaw of inner.split(',')) {
      const part = partRaw.trim().replace(/^type\s+/, '');
      if (part === '') continue;
      const pieces = part.split(/\s+as\s+/);
      const imported = (pieces[0] ?? '').trim();
      const local = (pieces[1] ?? pieces[0] ?? '').trim();
      if (imported && local) out.set(local, { spec, imported });
    }
  }
}

/** ES `import` and CommonJS `require` bindings (comments must already be stripped). */
export function parseImports(code: string): Map<string, ImportBinding> {
  const out = new Map<string, ImportBinding>();
  let m: RegExpExecArray | null;

  const importRe = /import\s+([^'";]+?)\s+from\s+['"]([^'"]+)['"]/g;
  while ((m = importRe.exec(code)) !== null) addImportClause(out, m[1] ?? '', m[2] ?? '');

  const requireRe = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  while ((m = requireRe.exec(code)) !== null) out.set(m[1] ?? '', { spec: m[2] ?? '', imported: 'default' });

  const destructRe = /(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  while ((m = destructRe.exec(code)) !== null) {
    for (const part of (m[1] ?? '').split(',')) {
      const pieces = part.split(':');
      const imported = (pieces[0] ?? '').trim();
      const local = (pieces[1] ?? pieces[0] ?? '').trim();
      if (imported && local) out.set(local, { spec: m[2] ?? '', imported });
    }
  }
  return out;
}

/** Resolves a relative import to a known project file. Aliases (@/, ~/) and packages return null. */
export function resolveRelativeImport(fromFile: string, spec: string, fileSet: ReadonlySet<string>): string | null {
  if (!spec.startsWith('.')) return null;
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(fromFile), spec));
  if (base.startsWith('..')) return null;
  const stripped = base.replace(/\.(m|c)?jsx?$/, '');
  const candidates: string[] = [base];
  for (const ext of RESOLVE_EXTS) {
    candidates.push(stripped + ext);
    candidates.push(`${stripped}/index${ext}`);
  }
  for (const candidate of candidates) {
    if (fileSet.has(candidate)) return candidate;
  }
  return null;
}

/** Which known variables (routers, apps, plugins) a module exports, by default or by name. */
export function parseExports(code: string, isKnownVar: (name: string) => boolean): ModuleExports {
  const out: ModuleExports = { named: new Map<string, string>() };
  let m: RegExpExecArray | null;

  const defaultRe = /export\s+default\s+([A-Za-z_$][\w$]*)/g;
  while ((m = defaultRe.exec(code)) !== null) {
    const name = m[1] ?? '';
    if (isKnownVar(name)) out.defaultVar = name;
  }

  const cjsRe = /module\s*\.\s*exports\s*=\s*([A-Za-z_$][\w$]*)/g;
  while ((m = cjsRe.exec(code)) !== null) {
    const name = m[1] ?? '';
    if (isKnownVar(name)) out.defaultVar = name;
  }

  const declRe = /export\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)/g;
  while ((m = declRe.exec(code)) !== null) {
    const name = m[1] ?? '';
    if (isKnownVar(name)) out.named.set(name, name);
  }

  const listRe = /export\s*\{([^}]*)\}/g;
  while ((m = listRe.exec(code)) !== null) {
    for (const partRaw of (m[1] ?? '').split(',')) {
      const pieces = partRaw.trim().split(/\s+as\s+/);
      const local = (pieces[0] ?? '').trim();
      const exported = (pieces[1] ?? pieces[0] ?? '').trim();
      if (!local || !isKnownVar(local)) continue;
      if (exported === 'default') out.defaultVar = local;
      else out.named.set(exported, local);
    }
  }

  const propRe = /(?:module\s*\.\s*)?exports\s*\.\s*([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)/g;
  while ((m = propRe.exec(code)) !== null) {
    const value = m[2] ?? '';
    if (isKnownVar(value)) out.named.set(m[1] ?? '', value);
  }
  return out;
}
