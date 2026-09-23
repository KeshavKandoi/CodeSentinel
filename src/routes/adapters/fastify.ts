import type { Confidence, Evidence } from '../../discovery/types.js';
import { classifyGuards, detectUploadIndicators, inlineAuthIndicators } from '../authHeuristics.js';
import { buildEntry, unique } from '../entryFactory.js';
import { parseImports, resolveRelativeImport } from '../jsModules.js';
import type { ImportBinding } from '../jsModules.js';
import { findObjectConst, parseObjectProps } from '../jsObjects.js';
import {
  argDisplayName,
  buildLineIndex,
  collectConstStrings,
  describeHandler,
  evalPathList,
  evalPathString,
  extractRequestUsage,
  findFunctionBody,
  findMatching,
  isFunctionLike,
  lineAtIndex,
  readCallArgs,
  splitArrayItems,
  stripJsComments,
  truncate,
} from '../jsScanner.js';
import type { CallArg } from '../jsScanner.js';
import { dedupeParams, expressPathParams, joinRoutePath, makeParam, toHttpMethod } from '../pathUtils.js';
import type { AdapterContext, AttackSurfaceEntry, FrameworkAdapter, HttpMethod, RouteParameter } from '../types.js';

const JS_EXTS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'] as const;
const FASTIFY_MENTION_RE = /['"]fastify['"]|fastify-plugin|@fastify\/|\bFastify(?:Instance|Plugin\w*|Request|Reply)\b/;
const EXPRESS_IMPORT_RE = /from\s+['"]express['"]|require\s*\(\s*['"]express['"]\s*\)/;
const AUTOLOAD_RE = /@fastify\/autoload|fastify-autoload/;
const CALL_RE_SRC =
  '\\b([A-Za-z_$][\\w$]*)\\s*\\.\\s*(get|post|put|patch|delete|head|options|all|route|register|addHook)\\s*(?:<[^()]*?>)?\\s*\\(';
const VERB_RE = /^(get|post|put|patch|delete|head|options|all)$/;
const LIFECYCLE: readonly string[] = ['onRequest', 'preParsing', 'preValidation', 'preHandler'];
const MAX_CHAINS = 50;
const BIG = 200_000;

const FASTIFY_INLINE_AUTHN: Array<[RegExp, string]> = [
  [/\b(?:request|req)\s*\.\s*jwtVerify\s*\(/, 'inline: request.jwtVerify()'],
  [/\b(?:request|req)\s*\.\s*user\b/, 'inline: request.user check'],
  [/\b(?:this|fastify|app|server|instance)\s*\.\s*authenticate\b/, 'inline: authenticate decorator'],
];

interface FnRange {
  param: string;
  name: string;
  declStart: number;
  bodyStart: number;
  bodyEnd: number;
  exportedDefault: boolean;
  typed: boolean;
}

interface FastifyModel {
  file: string;
  code: string;
  lineStarts: number[];
  consts: Map<string, string>;
  imports: Map<string, ImportBinding>;
  roots: Set<string>;
  ranges: FnRange[];
  defaultName: string;
  exportMap: Map<string, string>;
}

interface GuardInfo {
  names: string[];
  authn: string[];
  authz: string[];
}

interface HookRecord extends GuardInfo {
  stage: string;
  line: number;
}

interface RouteRecord {
  label: string;
  methods: HttpMethod[];
  pathText: string;
  declaredPaths: string[] | null;
  line: number;
  endLine: number;
  guardNames: string[];
  guardNotes: string[];
  inlineAuthn: string[];
  inlineAuthz: string[];
  handler: string;
  controller: string;
  handlerCode: string;
  schema: Map<string, string>;
  optsResolved: boolean;
}

interface Scope {
  key: string;
  file: string;
  label: string;
  kind: 'root' | 'plugin';
  range: FnRange | null;
  strong: boolean;
  registered: boolean;
  routes: RouteRecord[];
  hooks: HookRecord[];
}

interface PendingRegister {
  parent: string;
  file: string;
  line: number;
  args: CallArg[];
  text: string;
}

interface Edge {
  parent: string;
  child: string;
  prefix: string | null;
  line: number;
  text: string;
  guess: boolean;
}

interface BuildState {
  models: Map<string, FastifyModel>;
  fileSet: ReadonlySet<string>;
  scopes: Map<string, Scope>;
  byFile: Map<string, Scope[]>;
  pending: PendingRegister[];
  edges: Edge[];
  warnings: string[];
}

interface ChildRef {
  keys: string[];
  guess: boolean;
}

interface AppliedHook extends GuardInfo {
  stage: string;
  where: string;
}

interface Chain {
  prefix: string;
  resolved: boolean;
  guess: boolean;
  hooks: AppliedHook[];
  via: string[];
}

const UNRESOLVED_CHAIN: Chain = {
  prefix: '',
  resolved: false,
  guess: false,
  hooks: [],
  via: ['Plugin registration chain could not be resolved (circular or missing parent).'],
};

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function inlineIndicators(code: string): { authn: string[]; authz: string[] } {
  const base = inlineAuthIndicators(code);
  const authn = [...base.authn];
  for (const [re, label] of FASTIFY_INLINE_AUTHN) {
    if (re.test(code)) authn.push(label);
  }
  return { authn: unique(authn), authz: base.authz };
}

function analyzeGuards(val: string, code: string, stage: string): GuardInfo {
  const info: GuardInfo = { names: [], authn: [], authz: [] };
  for (const item of splitArrayItems(val)) {
    const display = argDisplayName(item);
    let body = '';
    if (display === '<inline function>') {
      info.names.push(`${stage} (inline)`);
      body = item;
    } else {
      info.names.push(display);
      if (/^[A-Za-z_$][\w$]*$/.test(display)) body = findFunctionBody(code, display) ?? '';
    }
    if (body !== '') {
      const ind = inlineIndicators(body);
      info.authn.push(...ind.authn.map((x) => `${stage} ${x}`));
      info.authz.push(...ind.authz.map((x) => `${stage} ${x}`));
    }
  }
  return info;
}

function resolveObjectText(text: string, code: string): string | null {
  const t = text.trim();
  if (t.startsWith('{')) return t;
  if (/^[A-Za-z_$][\w$]*$/.test(t)) return findObjectConst(code, t);
  return null;
}

function schemaParams(schema: Map<string, string>, sections: readonly string[]): RouteParameter[] {
  const out: RouteParameter[] = [];
  for (const section of sections) {
    const sec = schema.get(section);
    if (sec === undefined) continue;
    const secProps = parseObjectProps(sec);
    const properties = secProps.get('properties');
    if (properties === undefined) continue;
    const reqText = secProps.get('required');
    const required = new Set<string>(reqText === undefined ? [] : (evalPathList(reqText, new Map()) ?? []));
    for (const [name, def] of parseObjectProps(properties)) {
      const type = /\btype\s*:\s*['"](\w+)['"]/.exec(def)?.[1] ?? 'unknown';
      out.push(makeParam(name, type, reqText === undefined ? 'unknown' : required.has(name)));
    }
  }
  return out;
}

function mergeParams(primary: RouteParameter[], used: string[], whole: boolean, wholeLabel: string): RouteParameter[] {
  const merged = dedupeParams([...primary, ...used.map((n) => makeParam(n))]);
  if (merged.length === 0 && whole) merged.push(makeParam(wholeLabel));
  return merged;
}

function extractReplyIndicators(code: string): string[] {
  const out = new Set<string>();
  let m: RegExpExecArray | null;
  const methodRe = /\b(?:reply|res)\s*\.\s*(send|redirect|view|sendFile|download|type|header)\s*\(/g;
  while ((m = methodRe.exec(code)) !== null) out.add(`reply.${m[1] ?? ''}`);
  const codeRe = /\b(?:reply|res)\s*\.\s*(?:code|status)\s*\(\s*(\d{3})\s*\)/g;
  while ((m = codeRe.exec(code)) !== null) out.add(`status:${m[1] ?? ''}`);
  if (/\breturn\s+(?:\{|\[|['"`])/.test(code)) out.add('return: value');
  return Array.from(out);
}

function buildModel(file: string, raw: string): FastifyModel | null {
  const code = stripJsComments(raw);
  if (EXPRESS_IMPORT_RE.test(code) && !FASTIFY_MENTION_RE.test(code)) return null;
  const imports = parseImports(code);

  const factoryNames = new Set<string>(['Fastify', 'fastify']);
  for (const [local, binding] of imports) {
    if (binding.spec === 'fastify' && (binding.imported === 'default' || binding.imported === '*')) factoryNames.add(local);
  }
  const alt = Array.from(factoryNames).map(escapeRe).join('|');
  const rootRe = new RegExp(
    `(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*(?::[^=\\n]+?)?\\s*=\\s*(?:await\\s+)?(?:(?:${alt})|require\\s*\\(\\s*['"]fastify['"]\\s*\\))\\s*(?:<[^()]*?>)?\\s*\\(`,
    'g'
  );
  const roots = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = rootRe.exec(code)) !== null) {
    if (m[1]) roots.add(m[1]);
  }

  const receivers = new Set<string>();
  const callRe = new RegExp(CALL_RE_SRC, 'g');
  while ((m = callRe.exec(code)) !== null) receivers.add(m[1] ?? '');

  const ranges: FnRange[] = [];
  const addFn = (declStart: number, name: string, param: string, parenIdx: number, arrow: boolean): void => {
    const closeParen = findMatching(code, parenIdx, BIG);
    if (closeParen === -1) return;
    const tail = code.slice(closeParen + 1, closeParen + 300);
    const bm = (arrow ? /^\s*(?::[^={;]*)?=>\s*\{/ : /^\s*(?::[^{;=]*)?\{/).exec(tail);
    if (!bm) return;
    const bodyStart = closeParen + bm[0].length;
    const bodyEnd = findMatching(code, bodyStart, BIG);
    if (bodyEnd === -1) return;
    const before = code.slice(Math.max(0, declStart - 100), declStart);
    let fnName = name;
    if (fnName === '') {
      const nm = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:(?:fp|fastifyPlugin|plugin)\s*\(\s*)?$/.exec(before);
      fnName = nm?.[1] ?? '';
    }
    ranges.push({
      param,
      name: fnName,
      declStart,
      bodyStart,
      bodyEnd,
      exportedDefault: /(?:export\s+default\s+|module\s*\.\s*exports\s*=\s*)(?:(?:fp|fastifyPlugin|plugin)\s*\(\s*)?$/.test(before),
      typed: /Fastify\w*/.test(code.slice(parenIdx, closeParen)) || /Fastify\w*[^=\n]*=\s*(?:async\s*)?$/.test(before),
    });
  };

  for (const param of receivers) {
    const esc = escapeRe(param);
    const declRe = new RegExp(`(?:async\\s+)?function\\s*\\*?\\s*([A-Za-z_$][\\w$]*)?\\s*\\(\\s*${esc}\\b`, 'g');
    while ((m = declRe.exec(code)) !== null) addFn(m.index, m[1] ?? '', param, code.indexOf('(', m.index), false);
    const arrowRe = new RegExp(`(?:async\\s*)?\\(\\s*${esc}\\b`, 'g');
    while ((m = arrowRe.exec(code)) !== null) addFn(m.index, '', param, code.indexOf('(', m.index), true);
    const bareRe = new RegExp(`(?:async\\s+)?\\b${esc}\\s*=>\\s*\\{`, 'g');
    while ((m = bareRe.exec(code)) !== null) {
      const bodyStart = m.index + m[0].length - 1;
      const bodyEnd = findMatching(code, bodyStart, BIG);
      if (bodyEnd === -1) continue;
      ranges.push({ param, name: '', declStart: m.index, bodyStart, bodyEnd, exportedDefault: false, typed: false });
    }
  }

  let defaultName = '';
  const defRe = /(?:export\s+default\s+|module\s*\.\s*exports\s*=\s*)([A-Za-z_$][\w$]*)\s*(?:;|$)/gm;
  while ((m = defRe.exec(code)) !== null) {
    const n = m[1] ?? '';
    if (n !== 'async' && n !== 'function') defaultName = n;
  }
  const exportMap = new Map<string, string>();
  const declExportRe = /export\s+(?:async\s+)?(?:function\s*\*?\s*|const\s+|let\s+|var\s+)([A-Za-z_$][\w$]*)/g;
  while ((m = declExportRe.exec(code)) !== null) exportMap.set(m[1] ?? '', m[1] ?? '');
  const listExportRe = /export\s*\{([^}]*)\}/g;
  while ((m = listExportRe.exec(code)) !== null) {
    for (const part of (m[1] ?? '').split(',')) {
      const pieces = part.trim().split(/\s+as\s+/);
      const local = (pieces[0] ?? '').trim();
      const exported = (pieces[1] ?? pieces[0] ?? '').trim();
      if (local && exported) exportMap.set(exported, local);
    }
  }
  const propExportRe = /(?:module\s*\.\s*)?exports\s*\.\s*([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)/g;
  while ((m = propExportRe.exec(code)) !== null) exportMap.set(m[1] ?? '', m[2] ?? '');

  return {
    file,
    code,
    lineStarts: buildLineIndex(code),
    consts: collectConstStrings(code),
    imports,
    roots,
    ranges,
    defaultName,
    exportMap,
  };
}

function ensureScope(st: BuildState, model: FastifyModel, key: string, label: string, kind: 'root' | 'plugin', range: FnRange | null): Scope {
  let scope = st.scopes.get(key);
  if (!scope) {
    scope = { key, file: model.file, label, kind, range, strong: false, registered: false, routes: [], hooks: [] };
    st.scopes.set(key, scope);
    const list = st.byFile.get(model.file) ?? [];
    list.push(scope);
    st.byFile.set(model.file, list);
  }
  return scope;
}

function scopeFor(model: FastifyModel, receiver: string, idx: number, st: BuildState): Scope | null {
  let best: FnRange | null = null;
  for (const r of model.ranges) {
    if (r.param !== receiver || idx < r.bodyStart || idx > r.bodyEnd) continue;
    if (best === null || r.bodyStart > best.bodyStart) best = r;
  }
  if (best !== null) {
    const label = best.name !== '' ? best.name : `anonymous plugin (line ${lineAtIndex(model.lineStarts, best.declStart)})`;
    return ensureScope(st, model, `${model.file}::fn@${best.bodyStart}`, label, 'plugin', best);
  }
  if (model.roots.has(receiver)) return ensureScope(st, model, `${model.file}::${receiver}`, receiver, 'root', null);
  return null;
}

interface RecordInput {
  label: string;
  methods: HttpMethod[];
  pathText: string;
  line: number;
  endLine: number;
  props: Map<string, string>;
  optsResolved: boolean;
  handlerText: string;
}

function makeRecord(model: FastifyModel, input: RecordInput): RouteRecord {
  const guardNames: string[] = [];
  const guardNotes: string[] = [];
  const authn: string[] = [];
  const authz: string[] = [];
  for (const stage of LIFECYCLE) {
    const val = input.props.get(stage);
    if (val === undefined) continue;
    const g = analyzeGuards(val, model.code, stage);
    guardNames.push(...g.names);
    authn.push(...g.authn);
    authz.push(...g.authz);
    guardNotes.push(`${stage}: ${g.names.join(', ')}`);
  }

  let handlerCode = '';
  const ht = input.handlerText.trim();
  if (isFunctionLike(ht)) handlerCode = ht;
  else if (/^[A-Za-z_$][\w$]*$/.test(ht)) handlerCode = findFunctionBody(model.code, ht) ?? '';
  const { handler, controller } = describeHandler(ht);
  const inline = inlineIndicators(handlerCode);

  let schema = new Map<string, string>();
  const schemaText = input.props.get('schema');
  if (schemaText !== undefined) {
    const obj = resolveObjectText(schemaText, model.code);
    if (obj !== null) schema = parseObjectProps(obj);
  }

  return {
    label: input.label,
    methods: input.methods,
    pathText: input.pathText,
    declaredPaths: evalPathList(input.pathText, model.consts),
    line: input.line,
    endLine: input.endLine,
    guardNames,
    guardNotes,
    inlineAuthn: unique([...authn, ...inline.authn]),
    inlineAuthz: unique([...authz, ...inline.authz]),
    handler,
    controller,
    handlerCode,
    schema,
    optsResolved: input.optsResolved,
  };
}

function scanModel(model: FastifyModel, st: BuildState): void {
  const { code, file, lineStarts } = model;
  const callRe = new RegExp(CALL_RE_SRC, 'g');
  let m: RegExpExecArray | null;
  while ((m = callRe.exec(code)) !== null) {
    const recv = m[1] ?? '';
    const kind = m[2] ?? '';
    const scope = scopeFor(model, recv, m.index, st);
    if (!scope) continue;
    const line = lineAtIndex(lineStarts, m.index);
    const call = readCallArgs(code, m.index + m[0].length - 1);
    if (!call) {
      st.warnings.push(`${file}:${line}: could not parse arguments of ${recv}.${kind}(...); skipped.`);
      continue;
    }
    const args = call.args;
    const endLine = lineAtIndex(lineStarts, call.endIdx);

    if (kind === 'addHook') {
      scope.strong = true;
      const stage = args[0] ? (evalPathString(args[0].text, model.consts) ?? '') : '';
      if (!LIFECYCLE.includes(stage)) continue;
      const info: GuardInfo = { names: [], authn: [], authz: [] };
      for (const a of args.slice(1)) {
        const g = analyzeGuards(a.text, code, stage);
        info.names.push(...g.names);
        info.authn.push(...g.authn);
        info.authz.push(...g.authz);
      }
      scope.hooks.push({ stage, line, ...info });
      continue;
    }

    if (kind === 'register') {
      scope.strong = true;
      const a0 = args[0];
      if (!a0) continue;
      const a1 = args[1];
      const text = `${file}:${line}: ${recv}.register(${argDisplayName(a0.text)}${a1 ? `, ${truncate(a1.text.replace(/\s+/g, ' '), 60)}` : ''})`;
      st.pending.push({ parent: scope.key, file, line, args, text });
      continue;
    }

    if (kind === 'route') {
      scope.strong = true;
      const objText = args[0] ? resolveObjectText(args[0].text, code) : null;
      if (objText === null) {
        st.warnings.push(`${file}:${line}: route() options are not an object literal; route skipped.`);
        continue;
      }
      const props = parseObjectProps(objText);
      const urlText = props.get('url') ?? props.get('path');
      if (urlText === undefined) {
        st.warnings.push(`${file}:${line}: route() has no url/path property; route skipped.`);
        continue;
      }
      const methodText = props.get('method');
      const methodList = methodText === undefined ? null : evalPathList(methodText, model.consts);
      const unknownMethod: HttpMethod = 'unknown';
      scope.routes.push(
        makeRecord(model, {
          label: 'route()',
          methods: methodList === null ? [unknownMethod] : methodList.map(toHttpMethod),
          pathText: urlText,
          line,
          endLine,
          props,
          optsResolved: true,
          handlerText: props.get('handler') ?? '',
        })
      );
      continue;
    }

    if (VERB_RE.test(kind)) {
      const pathArg = args[0];
      if (args.length < 2 || !pathArg || isFunctionLike(pathArg.text)) continue;
      const rest = args.slice(1);
      let optsRaw: string | null = null;
      let handlerText = '';
      if (rest.length >= 2) {
        optsRaw = rest[0]?.text ?? null;
        handlerText = rest[rest.length - 1]?.text ?? '';
      } else {
        const only = rest[0]?.text ?? '';
        if (only.startsWith('{')) optsRaw = only;
        else handlerText = only;
      }
      let props = new Map<string, string>();
      let optsResolved = true;
      if (optsRaw !== null) {
        const objText = resolveObjectText(optsRaw, code);
        if (objText === null) optsResolved = false;
        else props = parseObjectProps(objText);
      }
      if (handlerText === '') handlerText = props.get('handler') ?? '';
      scope.routes.push(
        makeRecord(model, {
          label: kind.toUpperCase(),
          methods: [toHttpMethod(kind)],
          pathText: pathArg.text,
          line,
          endLine,
          props,
          optsResolved,
          handlerText,
        })
      );
    }
  }
}

function registerPrefix(arg: CallArg | undefined, model: FastifyModel): string | null {
  if (!arg) return '';
  const t = arg.text.trim();
  if (!t.startsWith('{')) return null; // options passed as a variable: prefix cannot be known
  const props = parseObjectProps(t);
  const prefix = props.get('prefix');
  if (prefix === undefined) return '';
  return evalPathString(prefix, model.consts);
}

function importedScope(fromFile: string, spec: string, imported: string, st: BuildState, line: number): ChildRef | null {
  if (!spec.startsWith('.')) return null;
  const target = resolveRelativeImport(fromFile, spec, st.fileSet);
  if (target === null) {
    st.warnings.push(`${fromFile}:${line}: could not resolve plugin import "${spec}"; routes registered through it may be missing.`);
    return null;
  }
  const tm = st.models.get(target);
  const candidates = (st.byFile.get(target) ?? []).filter((s) => s.kind === 'plugin' && s.range !== null);
  if (!tm || candidates.length === 0) return null;
  if (imported === 'default' || imported === '*') {
    const exact = candidates.filter((s) => s.range !== null && (s.range.exportedDefault || (s.range.name !== '' && s.range.name === tm.defaultName)));
    if (exact.length > 0) return { keys: exact.map((s) => s.key), guess: false };
    const only = candidates[0];
    if (candidates.length === 1 && only) return { keys: [only.key], guess: true };
    return null;
  }
  const local = tm.exportMap.get(imported) ?? imported;
  const named = candidates.filter((s) => s.range?.name === local);
  return named.length > 0 ? { keys: named.map((s) => s.key), guess: false } : null;
}

function resolveRegisterChild(arg: CallArg, model: FastifyModel, st: BuildState, line: number): ChildRef | null {
  let t = arg.text.trim();
  const wrapped = /^(?:fp|fastifyPlugin|plugin)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)$/.exec(t);
  if (wrapped) t = wrapped[1] ?? t;

  const req = /^require\s*\(\s*['"]([^'"]+)['"]\s*\)(?:\s*\.\s*([A-Za-z_$][\w$]*))?$/.exec(t);
  if (req) return importedScope(model.file, req[1] ?? '', req[2] ?? 'default', st, line);
  const dyn = /^import\s*\(\s*['"]([^'"]+)['"]\s*\)$/.exec(t);
  if (dyn) return importedScope(model.file, dyn[1] ?? '', 'default', st, line);

  const list = st.byFile.get(model.file) ?? [];
  if (isFunctionLike(t) || /^(?:fp|fastifyPlugin|plugin)\s*\(/.test(t)) {
    const inside = list
      .filter((s) => s.range !== null && s.range.declStart >= arg.start && s.range.declStart < arg.start + arg.text.length)
      .sort((a, b) => (a.range?.declStart ?? 0) - (b.range?.declStart ?? 0));
    const first = inside[0];
    return first ? { keys: [first.key], guess: false } : null;
  }
  if (/^[A-Za-z_$][\w$]*$/.test(t)) {
    const local = list.filter((s) => s.kind === 'plugin' && s.range?.name === t);
    if (local.length > 0) return { keys: local.map((s) => s.key), guess: false };
    const imp = model.imports.get(t);
    if (imp) return importedScope(model.file, imp.spec, imp.imported, st, line);
  }
  return null;
}

function resolveRegisters(st: BuildState): void {
  for (const p of st.pending) {
    const model = st.models.get(p.file);
    const a0 = p.args[0];
    if (!model || !a0) continue;
    const child = resolveRegisterChild(a0, model, st, p.line);
    if (!child) continue;
    const prefix = registerPrefix(p.args[1], model);
    for (const key of child.keys) {
      const target = st.scopes.get(key);
      if (target) target.registered = true;
      st.edges.push({ parent: p.parent, child: key, prefix, line: p.line, text: p.text, guess: child.guess });
    }
  }
}

function qualifies(scope: Scope, model: FastifyModel | undefined): boolean {
  if (scope.kind === 'root') return true;
  const r = scope.range;
  if (!r) return true;
  if (scope.strong || scope.registered || r.exportedDefault || r.typed) return true;
  if (model && r.name !== '' && (model.defaultName === r.name || Array.from(model.exportMap.values()).includes(r.name))) return true;
  return false;
}

function prune(st: BuildState): void {
  for (const [key, scope] of Array.from(st.scopes.entries())) {
    if (!qualifies(scope, st.models.get(scope.file))) st.scopes.delete(key);
  }
  st.edges = st.edges.filter((e) => st.scopes.has(e.parent) && st.scopes.has(e.child));
}

function appliedFrom(scope: Scope, beforeLine: number): AppliedHook[] {
  return scope.hooks
    .filter((h) => h.line < beforeLine)
    .map((h) => ({ stage: h.stage, names: h.names, authn: h.authn, authz: h.authz, where: `${scope.file}:${h.line}` }));
}

function chainsFor(key: string, st: BuildState, visiting: Set<string>): Chain[] {
  const scope = st.scopes.get(key);
  if (!scope) return [];
  if (visiting.has(key)) {
    st.warnings.push(`Circular plugin registration detected involving ${scope.file} "${scope.label}".`);
    return [];
  }
  const incoming = st.edges.filter((e) => e.child === key);
  if (incoming.length === 0) {
    if (scope.kind === 'root') return [{ prefix: '', resolved: true, guess: false, hooks: [], via: [] }];
    return [
      {
        prefix: '',
        resolved: false,
        guess: false,
        hooks: [],
        via: [`Plugin "${scope.label}" in ${scope.file} is not registered by any register() call found in analyzed source; URL prefix unknown.`],
      },
    ];
  }
  visiting.add(key);
  const out: Chain[] = [];
  for (const edge of incoming) {
    const parent = st.scopes.get(edge.parent);
    for (const pc of chainsFor(edge.parent, st, visiting)) {
      if (out.length >= MAX_CHAINS) break;
      out.push({
        prefix: edge.prefix === null ? pc.prefix : joinRoutePath(pc.prefix, edge.prefix),
        resolved: pc.resolved && edge.prefix !== null,
        guess: pc.guess || edge.guess,
        hooks: [...pc.hooks, ...(parent ? appliedFrom(parent, edge.line) : [])],
        via: [...pc.via, edge.text],
      });
    }
  }
  visiting.delete(key);
  return out;
}

function buildEntries(st: BuildState): AttackSurfaceEntry[] {
  const entries: AttackSurfaceEntry[] = [];
  for (const scope of st.scopes.values()) {
    if (scope.routes.length === 0) continue;
    const found = chainsFor(scope.key, st, new Set<string>());
    const chains: Chain[] = found.length > 0 ? found : [UNRESOLVED_CHAIN];

    for (const route of scope.routes) {
      const usage = extractRequestUsage(route.handlerCode);
      const own = appliedFrom(scope, route.line);
      const late = scope.hooks.filter((h) => h.line >= route.line && (classifyGuards(h.names).authentication.length > 0 || h.authn.length > 0));

      const schemaQuery = schemaParams(route.schema, ['querystring', 'query']);
      const schemaBody = schemaParams(route.schema, ['body']);
      const schemaPath = schemaParams(route.schema, ['params']);
      const queryParameters = mergeParams(schemaQuery, usage.query, usage.queryWhole, '(entire query)');
      const bodyParameters = mergeParams(schemaBody, usage.body, usage.bodyWhole, '(entire body)');

      const responseIndicators = extractReplyIndicators(route.handlerCode);
      const responseSchema = route.schema.get('response');
      if (responseSchema !== undefined) {
        for (const k of parseObjectProps(responseSchema).keys()) responseIndicators.push(`schema:response:${k}`);
      }

      const declared: Array<string | null> = route.declaredPaths ?? [null];
      for (const chain of chains) {
        const hooks = [...chain.hooks, ...own];
        for (const dp of declared) {
          for (const method of route.methods) {
            const pathResolved = dp !== null && chain.resolved;
            const fullPath = dp === null ? 'unknown' : joinRoutePath(chain.prefix, dp);
            const middleware = unique([...hooks.flatMap((h) => h.names), ...route.guardNames]);
            const uploads = detectUploadIndicators(middleware, route.handlerCode);
            if (/\b(?:request|req)\s*\.\s*(?:file|files|parts|saveRequestFiles|isMultipart)\s*\(/.test(route.handlerCode)) {
              uploads.push('code: request.file()/files()/parts()');
            }

            const evidence: Evidence[] = [
              {
                source: `${scope.file}:${route.line}`,
                detail: `Fastify ${route.label} route declared on ${scope.kind} "${scope.label}" with path argument ${truncate(route.pathText, 80)}`,
              },
            ];
            for (const via of chain.via) evidence.push({ source: 'mount-resolution', detail: via });
            for (const h of hooks) {
              if (h.names.length > 0) evidence.push({ source: 'hook', detail: `${h.stage} hook at ${h.where} applies: ${h.names.join(', ')}` });
            }
            if (route.guardNotes.length > 0) {
              evidence.push({ source: `${scope.file}:${route.line}`, detail: `Route-level hooks: ${route.guardNotes.join('; ')}` });
            }
            for (const h of late) {
              evidence.push({
                source: 'hook-ordering',
                detail: `${h.stage} hook at ${scope.file}:${h.line} is declared after this route and is not counted as protection; verify whether Fastify applies it here.`,
              });
            }
            if (dp === null) {
              evidence.push({ source: `${scope.file}:${route.line}`, detail: 'Route path is not a static string; recorded as unknown instead of guessing.' });
            }
            if (!route.optsResolved) {
              evidence.push({ source: `${scope.file}:${route.line}`, detail: 'Route options are not an inline object; route-level hooks and schema could not be read.' });
            }

            let confidence: Confidence = 'high';
            if (!pathResolved) confidence = 'low';
            else if (chain.guess || !route.optsResolved) confidence = 'medium';

            entries.push(
              buildEntry({
                framework: 'fastify',
                method,
                path: fullPath,
                pathResolved,
                file: scope.file,
                line: route.line,
                endLine: route.endLine,
                handler: route.handler,
                controller: route.controller,
                router: `${scope.file}#${scope.label}`,
                middleware,
                dependencies: [],
                parameters: dedupeParams([...schemaPath, ...expressPathParams(fullPath)]),
                queryParameters,
                bodyParameters,
                extraAuth: unique([...hooks.flatMap((h) => h.authn), ...route.inlineAuthn]),
                extraAuthz: unique([...hooks.flatMap((h) => h.authz), ...route.inlineAuthz]),
                uploadIndicators: uploads,
                responseIndicators,
                confidence,
                evidence,
              })
            );
          }
        }
      }
    }
  }
  return entries;
}

export const fastifyAdapter: FrameworkAdapter = {
  id: 'fastify',
  ecosystems: ['node'],

  appliesTo(ctx: AdapterContext): boolean {
    if (ctx.profile.ecosystem !== 'node') return false;
    return (
      ctx.profile.dependencies.some((d) => d.name === 'fastify') ||
      ctx.profile.frameworks.backend.some((f) => f.name.toLowerCase() === 'fastify')
    );
  },

  discover(ctx: AdapterContext): AttackSurfaceEntry[] {
    const files = ctx.listSourceFiles(JS_EXTS);
    const fileSet = new Set(files);
    const models = new Map<string, FastifyModel>();
    let autoload = false;
    for (const file of files) {
      const src = ctx.readSource(file);
      if (!src) continue;
      const model = buildModel(file, src.content);
      if (!model) continue;
      if (AUTOLOAD_RE.test(model.code)) autoload = true;
      if (model.roots.size > 0 || model.ranges.length > 0) models.set(file, model);
    }

    const st: BuildState = { models, fileSet, scopes: new Map(), byFile: new Map(), pending: [], edges: [], warnings: ctx.warnings };
    for (const model of models.values()) scanModel(model, st);
    resolveRegisters(st);
    prune(st);
    if (autoload) {
      ctx.warnings.push(
        'Fastify autoload detected: routes loaded from directories cannot be resolved statically. Plugins without a static register() call are reported with an unresolved URL prefix.'
      );
    }
    return buildEntries(st);
  },
};
