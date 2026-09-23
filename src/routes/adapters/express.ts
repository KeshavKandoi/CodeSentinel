import type { Confidence, Evidence } from '../../discovery/types.js';
import { detectUploadIndicators, inlineAuthIndicators } from '../authHeuristics.js';
import { buildEntry, unique } from '../entryFactory.js';
import { parseExports, parseImports, resolveRelativeImport } from '../jsModules.js';
import type { ImportBinding, ModuleExports } from '../jsModules.js';
import {
  argDisplayName,
  buildLineIndex,
  collectConstStrings,
  describeHandler,
  evalPathList,
  extractRequestUsage,
  extractResponseIndicators,
  findFunctionBody,
  flattenArgNames,
  isFunctionLike,
  isPathLike,
  lineAtIndex,
  readCallArgs,
  stripJsComments,
  truncate,
} from '../jsScanner.js';
import type { CallArg } from '../jsScanner.js';
import { dedupeParams, expressPathParams, joinRoutePath, makeParam, pathStartsWith, toHttpMethod } from '../pathUtils.js';
import type { AdapterContext, AttackSurfaceEntry, FrameworkAdapter, HttpMethod } from '../types.js';

const JS_EXTS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'] as const;
const EXPRESS_IMPORT_RE = /from\s+['"]express['"]|require\s*\(\s*['"]express['"]\s*\)/;
const MAX_CHAINS = 50;

type NodeKind = 'app' | 'router';

interface RawRoute {
  verb: string;
  method: HttpMethod;
  pathText: string;
  declaredPaths: string[] | null;
  line: number;
  endLine: number;
  middleware: string[];
  handler: string;
  controller: string;
  handlerCode: string;
}

interface UseRecord {
  line: number;
  hasPath: boolean;
  prefixes: Array<string | null>;
  middleware: string[];
}

interface RouterNode {
  key: string;
  file: string;
  varName: string;
  kind: NodeKind;
  routes: RawRoute[];
  uses: UseRecord[];
}

interface MountEdge {
  parent: string;
  child: string;
  prefixes: Array<string | null>; // null = prefix not statically resolvable
  middleware: string[];
  line: number;
  text: string;
  guess: boolean;
}

interface FileModel {
  file: string;
  code: string;
  lineStarts: number[];
  consts: Map<string, string>;
  imports: Map<string, ImportBinding>;
  vars: Map<string, NodeKind>;
  exports: ModuleExports;
}

interface BuildState {
  nodes: Map<string, RouterNode>;
  edges: MountEdge[];
  models: Map<string, FileModel>;
  fileSet: ReadonlySet<string>;
  warnings: string[];
}

interface ChildRef {
  keys: string[];
  guess: boolean;
}

interface Chain {
  prefix: string;
  resolved: boolean;
  guess: boolean;
  middleware: string[];
  via: string[];
}

function nodeKey(file: string, varName: string): string {
  return `${file}::${varName}`;
}

function buildModel(file: string, raw: string): FileModel | null {
  const code = stripJsComments(raw);
  if (!EXPRESS_IMPORT_RE.test(code)) return null;

  const vars = new Map<string, NodeKind>();
  const collect = (re: RegExp, kind: NodeKind): void => {
    let m: RegExpExecArray | null;
    while ((m = re.exec(code)) !== null) {
      const name = m[1];
      if (name && !vars.has(name)) vars.set(name, kind);
    }
  };
  collect(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[^=\n]+?)?\s*=\s*express\s*\(/g, 'app');
  collect(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[^=\n]+?)?\s*=\s*(?:express\s*\.\s*)?Router\s*\(/g, 'router');
  collect(/\b([A-Za-z_$][\w$]*)\s*:\s*(?:express\s*\.\s*)?Router\b(?!\s*\.)/g, 'router');
  collect(/\b([A-Za-z_$][\w$]*)\s*:\s*(?:express\s*\.\s*)?(?:Express|Application)\b(?!\s*\.)/g, 'app');

  return {
    file,
    code,
    lineStarts: buildLineIndex(code),
    consts: collectConstStrings(code),
    imports: parseImports(code),
    vars,
    exports: parseExports(code, (n) => vars.has(n)),
  };
}

function resolveImportedRouter(fromFile: string, spec: string, imported: string, st: BuildState): ChildRef | null {
  const target = resolveRelativeImport(fromFile, spec, st.fileSet);
  if (!target) return null;
  const tm = st.models.get(target);
  if (!tm) return null;

  const exportedVar = imported === 'default' || imported === '*' ? tm.exports.defaultVar : tm.exports.named.get(imported);
  if (exportedVar && tm.vars.has(exportedVar)) return { keys: [nodeKey(target, exportedVar)], guess: false };

  // No explicit export found: only accept it when the file has exactly one router (flagged as a lower-confidence guess).
  if (imported === 'default') {
    const routers = Array.from(tm.vars.entries()).filter(([, kind]) => kind === 'router');
    const only = routers[0];
    if (routers.length === 1 && only) return { keys: [nodeKey(target, only[0])], guess: true };
  }
  return null;
}

function resolveChild(argText: string, model: FileModel, st: BuildState): ChildRef | null {
  const t = argText.trim();
  const req = /^require\s*\(\s*['"]([^'"]+)['"]\s*\)(?:\s*\.\s*([A-Za-z_$][\w$]*))?$/.exec(t);
  if (req) return resolveImportedRouter(model.file, req[1] ?? '', req[2] ?? 'default', st);
  if (!/^[A-Za-z_$][\w$]*$/.test(t)) return null;
  if (model.vars.has(t)) return { keys: [nodeKey(model.file, t)], guess: false };
  const imp = model.imports.get(t);
  if (!imp) return null;
  return resolveImportedRouter(model.file, imp.spec, imp.imported, st);
}

function makeRoute(
  model: FileModel,
  verb: string,
  pathText: string,
  restArgs: readonly CallArg[],
  startIdx: number,
  endIdx: number
): RawRoute {
  const handlerArg = restArgs[restArgs.length - 1];
  const handlerText = handlerArg ? handlerArg.text : '';
  const { handler, controller } = describeHandler(handlerText);
  let handlerCode = '';
  if (isFunctionLike(handlerText)) handlerCode = handlerText;
  else if (/^[A-Za-z_$][\w$]*$/.test(handlerText)) handlerCode = findFunctionBody(model.code, handlerText) ?? '';
  return {
    verb,
    method: toHttpMethod(verb),
    pathText,
    declaredPaths: evalPathList(pathText, model.consts),
    line: lineAtIndex(model.lineStarts, startIdx),
    endLine: lineAtIndex(model.lineStarts, endIdx),
    middleware: flattenArgNames(restArgs.slice(0, -1)),
    handler,
    controller,
    handlerCode,
  };
}

function scanModel(model: FileModel, st: BuildState): void {
  const { code, file, lineStarts } = model;
  let m: RegExpExecArray | null;

  // 1) app.get('/x', ...), router.post('/y', ...)
  const callRe = /\b([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|patch|delete|head|options|all)\s*\(/g;
  while ((m = callRe.exec(code)) !== null) {
    const recv = m[1] ?? '';
    const node = st.nodes.get(nodeKey(file, recv));
    if (!node) continue;
    const call = readCallArgs(code, m.index + m[0].length - 1);
    if (!call) {
      st.warnings.push(`${file}:${lineAtIndex(lineStarts, m.index)}: could not parse arguments of ${recv}.${m[2] ?? ''}(...); route skipped.`);
      continue;
    }
    const pathArg = call.args[0];
    // app.get('setting') is Express's settings getter, not a route.
    if (call.args.length < 2 || !pathArg || isFunctionLike(pathArg.text)) continue;
    node.routes.push(makeRoute(model, m[2] ?? '', pathArg.text, call.args.slice(1), m.index, call.endIdx));
  }

  // 2) router.route('/x').get(h).post(h2)
  const routeRe = /\b([A-Za-z_$][\w$]*)\s*\.\s*route\s*\(/g;
  while ((m = routeRe.exec(code)) !== null) {
    const node = st.nodes.get(nodeKey(file, m[1] ?? ''));
    if (!node) continue;
    const call = readCallArgs(code, m.index + m[0].length - 1);
    const pathArg = call?.args[0];
    if (!call || !pathArg) continue;
    let cursor = call.endIdx + 1;
    for (let guard = 0; guard < 20; guard++) {
      const cm = /^\s*\.\s*(get|post|put|patch|delete|head|options|all)\s*\(/.exec(code.slice(cursor, cursor + 120));
      if (!cm) break;
      const chained = readCallArgs(code, cursor + cm[0].length - 1);
      if (!chained) break;
      const dotIdx = cursor + cm[0].indexOf('.');
      if (chained.args.length > 0) {
        node.routes.push(makeRoute(model, cm[1] ?? '', pathArg.text, chained.args, dotIdx, chained.endIdx));
      }
      cursor = chained.endIdx + 1;
    }
  }

  // 3) app.use(...) / router.use(...): mounts and middleware
  const useRe = /\b([A-Za-z_$][\w$]*)\s*\.\s*use\s*\(/g;
  while ((m = useRe.exec(code)) !== null) {
    const recv = m[1] ?? '';
    const parentKey = nodeKey(file, recv);
    const node = st.nodes.get(parentKey);
    if (!node) continue;
    const call = readCallArgs(code, m.index + m[0].length - 1);
    if (!call || call.args.length === 0) continue;
    const line = lineAtIndex(lineStarts, m.index);

    let rest: readonly CallArg[] = call.args;
    let hasPath = false;
    let prefixes: Array<string | null> = [''];
    const first = call.args[0];
    if (first && isPathLike(first.text, model.consts)) {
      hasPath = true;
      prefixes = evalPathList(first.text, model.consts) ?? [null];
      rest = call.args.slice(1);
    } else if (first && !isFunctionLike(first.text) && first.text.includes('+') && /['"]/.test(first.text)) {
      // Computed prefix such as getBase() + '/x': never guess, mark it unresolved.
      hasPath = true;
      prefixes = [null];
      rest = call.args.slice(1);
    }

    const middleware: string[] = [];
    const children: ChildRef[] = [];
    for (const arg of rest) {
      const child = resolveChild(arg.text, model, st);
      if (child) {
        children.push(child);
        continue;
      }
      middleware.push(...flattenArgNames([arg]));
      const id = arg.text.trim();
      const imp = model.imports.get(id);
      if (imp && /rout/i.test(id)) {
        st.warnings.push(
          `${file}:${line}: could not resolve mounted router "${id}" (import "${imp.spec}"); its routes will have an unresolved URL prefix.`
        );
      }
    }

    const text = truncate(`${recv}.use(${call.args.map((a) => argDisplayName(a.text)).join(', ')})`, 140);
    if (children.length > 0) {
      for (const child of children) {
        for (const key of child.keys) {
          st.edges.push({ parent: parentKey, child: key, prefixes, middleware, line, text: `${file}:${line}: ${text}`, guess: child.guess });
        }
      }
    } else {
      node.uses.push({ line, hasPath, prefixes, middleware });
    }
  }
}

/** Middleware registered with .use() on `node` before `beforeLine` that applies to `pathHint`. */
function applicableUses(node: RouterNode, beforeLine: number, pathHint: string): string[] {
  const out: string[] = [];
  for (const u of node.uses) {
    if (u.line >= beforeLine) continue;
    if (!u.hasPath) {
      out.push(...u.middleware);
      continue;
    }
    const hint = pathHint === '' ? '/' : pathHint;
    if (u.prefixes.some((p) => p !== null && pathStartsWith(hint, p))) out.push(...u.middleware);
  }
  return out;
}

function chainsFor(key: string, st: BuildState, visiting: Set<string>): Chain[] {
  const node = st.nodes.get(key);
  if (!node) return [];
  if (visiting.has(key)) {
    st.warnings.push(`Circular router mount detected involving ${node.file} "${node.varName}".`);
    return [];
  }
  const incoming = st.edges.filter((e) => e.child === key);
  if (incoming.length === 0) {
    if (node.kind === 'app') return [{ prefix: '', resolved: true, guess: false, middleware: [], via: [] }];
    return [
      {
        prefix: '',
        resolved: false,
        guess: false,
        middleware: [],
        via: [`Router "${node.varName}" in ${node.file} is not mounted by any app.use()/router.use() call found in analyzed source; URL prefix unknown.`],
      },
    ];
  }

  visiting.add(key);
  const out: Chain[] = [];
  for (const edge of incoming) {
    const parent = st.nodes.get(edge.parent);
    for (const pc of chainsFor(edge.parent, st, visiting)) {
      for (const p of edge.prefixes) {
        if (out.length >= MAX_CHAINS) break;
        const inherited = parent ? applicableUses(parent, edge.line, p ?? '') : [];
        out.push({
          prefix: p === null ? pc.prefix : joinRoutePath(pc.prefix, p),
          resolved: pc.resolved && p !== null,
          guess: pc.guess || edge.guess,
          middleware: [...pc.middleware, ...inherited, ...edge.middleware],
          via: [...pc.via, edge.text],
        });
      }
    }
  }
  visiting.delete(key);
  return out;
}

const UNRESOLVED_CHAIN: Chain = {
  prefix: '',
  resolved: false,
  guess: false,
  middleware: [],
  via: ['Router mount chain could not be resolved (circular or missing parent).'],
};

function buildEntries(st: BuildState): AttackSurfaceEntry[] {
  const entries: AttackSurfaceEntry[] = [];
  for (const node of st.nodes.values()) {
    if (node.routes.length === 0) continue;
    const found = chainsFor(node.key, st, new Set<string>());
    const chains: Chain[] = found.length > 0 ? found : [UNRESOLVED_CHAIN];

    for (const route of node.routes) {
      const usage = extractRequestUsage(route.handlerCode);
      const inline = inlineAuthIndicators(route.handlerCode);
      const responseIndicators = extractResponseIndicators(route.handlerCode);
      const queryParameters = usage.query.map((n) => makeParam(n));
      if (usage.queryWhole && queryParameters.length === 0) queryParameters.push(makeParam('(entire query)'));
      const bodyParameters = usage.body.map((n) => makeParam(n));
      if (usage.bodyWhole && bodyParameters.length === 0) bodyParameters.push(makeParam('(entire body)'));
      const declared: Array<string | null> = route.declaredPaths ?? [null];

      for (const chain of chains) {
        for (const dp of declared) {
          const pathResolved = dp !== null && chain.resolved;
          const fullPath = dp === null ? 'unknown' : joinRoutePath(chain.prefix, dp);
          const middleware = unique([...chain.middleware, ...applicableUses(node, route.line, dp ?? ''), ...route.middleware]);

          const evidence: Evidence[] = [
            {
              source: `${node.file}:${route.line}`,
              detail: `Express ${route.verb.toUpperCase()} route declared on ${node.kind} "${node.varName}" with path argument ${truncate(route.pathText, 80)}`,
            },
          ];
          for (const via of chain.via) evidence.push({ source: 'mount-resolution', detail: via });
          if (dp === null) {
            evidence.push({ source: `${node.file}:${route.line}`, detail: 'Route path is not a static string; recorded as unknown instead of guessing.' });
          }

          let confidence: Confidence = 'high';
          if (!pathResolved) confidence = 'low';
          else if (chain.guess) confidence = 'medium';

          entries.push(
            buildEntry({
              framework: 'express',
              method: route.method,
              path: fullPath,
              pathResolved,
              file: node.file,
              line: route.line,
              endLine: route.endLine,
              handler: route.handler,
              controller: route.controller,
              router: `${node.file}#${node.varName}`,
              middleware,
              dependencies: [],
              parameters: dedupeParams(expressPathParams(fullPath)),
              queryParameters,
              bodyParameters,
              extraAuth: inline.authn,
              extraAuthz: inline.authz,
              uploadIndicators: detectUploadIndicators(middleware, route.handlerCode),
              responseIndicators,
              confidence,
              evidence,
            })
          );
        }
      }
    }
  }
  return entries;
}

export const expressAdapter: FrameworkAdapter = {
  id: 'express',
  ecosystems: ['node'],

  appliesTo(ctx: AdapterContext): boolean {
    if (ctx.profile.ecosystem !== 'node') return false;
    return (
      ctx.profile.dependencies.some((d) => d.name === 'express') ||
      ctx.profile.frameworks.backend.some((f) => f.name.toLowerCase() === 'express')
    );
  },

  discover(ctx: AdapterContext): AttackSurfaceEntry[] {
    const files = ctx.listSourceFiles(JS_EXTS);
    const fileSet = new Set(files);
    const models = new Map<string, FileModel>();
    for (const file of files) {
      const src = ctx.readSource(file);
      if (!src) continue;
      const model = buildModel(file, src.content);
      if (model && model.vars.size > 0) models.set(file, model);
    }

    const st: BuildState = { nodes: new Map(), edges: [], models, fileSet, warnings: ctx.warnings };
    for (const model of models.values()) {
      for (const [name, kind] of model.vars) {
        const key = nodeKey(model.file, name);
        st.nodes.set(key, { key, file: model.file, varName: name, kind, routes: [], uses: [] });
      }
    }
    for (const model of models.values()) scanModel(model, st);
    return buildEntries(st);
  },
};
