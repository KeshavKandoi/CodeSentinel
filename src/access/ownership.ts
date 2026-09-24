import type { Confidence } from '../discovery/types.js';
import type { AttackSurfaceEntry } from '../routes/types.js';
import { REJECT_RE } from './patterns.js';
import { escapeRegExp } from './text.js';
import type { RouteSource } from './text.js';
import type { IdentitySource, OwnershipKind, ResourceLoad, ResourceOperation, ResourceOwnershipCheck } from './types.js';

export interface OwnershipAnalysis {
  resourceParameters: string[];
  loads: ResourceLoad[];
  checks: ResourceOwnershipCheck[];
}

const LOAD_RE_JS = /\.\s*(?:findById|findByPk|findOne|findOneBy|findOneOrFail|findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|findOneAndUpdate|findOneAndDelete|findOneAndRemove|findAll|find|findMany|update|updateOne|updateMany|delete|deleteOne|deleteMany|destroy|remove|removeById|softDelete|save|upsert|getById|getOne|fetchOne|retrieve|select|query|execute|raw|populate)\s*\(|\b(?:get|fetch|load|find|read|retrieve|update|delete|remove|destroy)[A-Z_]\w*\s*\(/;
const LOAD_RE_PY = /\bget_object_or_404\s*\(|\bget_list_or_404\s*\(|\.\s*objects\s*\.\s*(?:get|filter|exclude|select_for_update|update|delete|all)\s*\(|\.\s*(?:get|filter|filter_by|exclude|first|one|one_or_none|scalar|scalars|execute|query|delete|update|merge|add|commit|refresh|select_for_update|save)\s*\(|\bselect\s*\(|\b(?:get|fetch|load|find|read|retrieve|update|delete|remove|destroy|save)_\w+\s*\(/;
const COMPARE_RE = /===|!==|==|!=|\.\s*equals\s*\(|\.\s*includes\s*\(|\.\s*has\s*\(|\bis\s+not\b|\bis\b|\bnot\s+in\b|\bin\b/;
const OWNER_PROP_RE = /\.\s*(?:owner|ownerId|owner_id|userId|user_id|user|users|author|authorId|author_id|createdBy|created_by|creator|customerId|customer_id|accountId|account_id|ownedBy|owned_by|members|memberIds|participants|assignee|assigneeId|assigned_to|tenantId|tenant_id|orgId|org_id|organizationId|organization_id|workspaceId|workspace_id)(?![\w$])/;
const TENANT_RE = /tenant|organi[sz]ation|\borg(?:Id|_id)\b|workspace/i;
const POLICY_CALL_RE = /(?<![\w$])((?:[A-Za-z_$][\w$]*\s*\.\s*)*)(isOwner|isOwnedBy|checkOwner(?:ship)?|assertOwner(?:ship)?|verifyOwner(?:ship)?|ownsResource|canAccess|canView|canRead|canEdit|canUpdate|canDelete|can|cannot|authorize|authorise|check_object_permissions|has_object_permission|checkPolicy|enforce|assertCan|userCan|user_can)\s*\(([^\n]{0,200})/g;

export function isResourceParameter(name: string): boolean {
  return /^(?:id|uuid|guid|pk|_id)$/i.test(name) || /(?:[a-z0-9]Id|[a-z0-9]ID|_id|_uuid|_pk|Uuid|Guid)$/.test(name);
}

function aliasRegex(alias: string): RegExp {
  return new RegExp(`(?<![\\w$.])${escapeRegExp(alias)}(?![\\w$])`);
}

function jsAliases(param: string, joined: string, rawCode: string): string[] {
  const out = new Set<string>();
  for (const base of ['req.params', 'request.params', 'ctx.params', 'context.params', 'params', 'req.query', 'request.query']) out.add(`${base}.${param}`);
  const destructure = /(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?(?:req\.params|request\.params|ctx\.params|context\.params|params|req\.query|request\.query)(?![\w$])/g;
  for (const m of joined.matchAll(destructure)) {
    for (const piece of (m[1] ?? '').split(',')) {
      const [keyRaw, aliasRaw] = piece.split(':');
      const key = (keyRaw ?? '').trim().replace(/\s*=.*$/, '');
      if (key !== param) continue;
      const alias = (aliasRaw ?? key).trim().replace(/\s*=.*$/, '');
      if (/^[A-Za-z_$][\w$]*$/.test(alias)) out.add(alias);
    }
  }
  const nest = new RegExp(`@Param\\s*\\(\\s*['"]${escapeRegExp(param)}['"]\\s*\\)\\s*(?:readonly\\s+)?([A-Za-z_$][\\w$]*)`, 'g');
  for (const m of rawCode.matchAll(nest)) if (m[1]) out.add(m[1]);
  for (const known of Array.from(out)) {
    const assign = new RegExp(`(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*(?::[^=\\n]+)?=[^;\\n]*?(?<![\\w$.])${escapeRegExp(known)}(?![\\w$])`, 'g');
    for (const m of joined.matchAll(assign)) if (m[1]) out.add(m[1]);
  }
  return Array.from(out);
}

function pyAliases(param: string, joined: string): string[] {
  const out = new Set<string>([param]);
  const assign = new RegExp(`^\\s*([A-Za-z_]\\w*)\\s*(?::[^=\\n]+)?=(?!=)[^\\n]*?(?<![\\w.])${escapeRegExp(param)}(?!\\w)`, 'gm');
  for (const m of joined.matchAll(assign)) if (m[1]) out.add(m[1]);
  return Array.from(out);
}

function statementFrom(lines: readonly string[], start: number): string {
  let depth = 0;
  const parts: string[] = [];
  for (let j = start; j < lines.length && j < start + 8; j++) {
    const l = lines[j] ?? '';
    parts.push(l);
    for (const ch of l) {
      if (ch === '(' || ch === '[' || ch === '{') depth++;
      else if (ch === ')' || ch === ']' || ch === '}') depth--;
    }
    if (depth <= 0) break;
  }
  return parts.join(' ');
}

function operationOf(text: string, method: string): ResourceOperation {
  if (/delete|remove|destroy/i.test(text)) return 'delete';
  if (/update|save|upsert|merge|\.add\s*\(|create|patch|insert|commit/i.test(text)) return 'write';
  if (method === 'DELETE') return 'delete';
  if (method === 'PUT' || method === 'PATCH' || method === 'POST') return 'write';
  return method === 'GET' || method === 'HEAD' ? 'read' : 'unknown';
}

function assignedVariable(lines: readonly string[], from: number, to: number): string | null {
  let found: string | null = null;
  for (let j = Math.max(0, from); j <= to && j < lines.length; j++) {
    const l = lines[j] ?? '';
    const m = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=/.exec(l) ?? /^\s*([A-Za-z_]\w*)\s*=(?!=)/.exec(l);
    if (m?.[1]) found = m[1];
  }
  return found;
}

function snippet(text: string): string {
  return text.trim().replace(/\s+/g, ' ').slice(0, 160);
}

export function analyzeOwnership(entry: AttackSurfaceEntry, source: RouteSource, identities: readonly IdentitySource[]): OwnershipAnalysis {
  const resourceParameters = Array.from(new Set(entry.parameters.map((p) => p.name).filter(isResourceParameter)));
  const loads: ResourceLoad[] = [];
  const checks: ResourceOwnershipCheck[] = [];
  const idNames = Array.from(new Set(identities.map((i) => i.name))).sort((a, b) => b.length - a.length);
  const idAlt = idNames.map(escapeRegExp).join('|');
  const refRe = idAlt === '' ? null : new RegExp(`(?<![\\w$.])(?:${idAlt})(?![\\w$])(?!\\s*:)`);
  const seenLoads = new Set<string>();
  const seenChecks = new Set<string>();

  for (const part of source.parts) {
    const python = part.file.endsWith('.py');
    const lines = part.plain.split('\n');
    const rawLines = part.code.split('\n');
    const joined = lines.join('\n');
    const loadRe = python ? LOAD_RE_PY : LOAD_RE_JS;
    const aliasByParam = new Map<string, RegExp[]>();
    for (const p of resourceParameters) {
      const names = python ? pyAliases(p, joined) : jsAliases(p, joined, part.code);
      aliasByParam.set(p, names.map(aliasRegex));
    }
    const aliasHit = (text: string): string | null => {
      for (const [p, regs] of aliasByParam) if (regs.some((r) => r.test(text))) return p;
      return null;
    };
    const loadedVars = new Set<string>();

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      const windowText = lines.slice(Math.max(0, i - 2), i + 2).join(' ');
      for (const [param, regs] of aliasByParam) {
        if (!regs.some((r) => r.test(line)) || !loadRe.test(windowText)) continue;
        const key = `${param}|${part.file}|${part.startLine + i}`;
        if (seenLoads.has(key)) continue;
        seenLoads.add(key);
        loads.push({
          parameter: param,
          expression: snippet(rawLines[i] ?? ''),
          operation: operationOf(windowText, entry.method),
          file: part.file,
          line: part.startLine + i,
        });
        const assigned = assignedVariable(lines, i - 2, i);
        if (assigned) loadedVars.add(assigned);
      }
    }

    const loadedRe = loadedVars.size === 0 ? null : new RegExp(`(?<![\\w$.])(?:${Array.from(loadedVars).map(escapeRegExp).join('|')})\\s*\\.`);
    const pushCheck = (kind: OwnershipKind, parameter: string, identity: string, i: number, confidence: Confidence, detail: string): void => {
      const key = `${kind}|${part.file}|${part.startLine + i}`;
      if (seenChecks.has(key)) return;
      seenChecks.add(key);
      checks.push({
        kind,
        parameter,
        identity,
        expression: snippet(rawLines[i] ?? ''),
        file: part.file,
        line: part.startLine + i,
        confidence,
        evidence: [{ source: `${part.file}:${part.startLine + i}`, detail }],
      });
    };

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      if (line.trim() === '') continue;
      const rejects = REJECT_RE.test(lines.slice(i, i + 3).join(' '));

      if (refRe && loadRe.test(line)) {
        const statement = statementFrom(lines, i);
        const ref = refRe.exec(statement);
        if (ref) {
          const param = aliasHit(statement);
          pushCheck(
            'scoped_query',
            param ?? '*',
            ref[0],
            i,
            param ? 'high' : 'medium',
            `Data access is scoped by the authenticated identity "${ref[0]}"${param ? ` together with the "${param}" path parameter` : ''}.`
          );
        }
      }

      if (refRe && COMPARE_RE.test(line)) {
        const ref = refRe.exec(line);
        const param = aliasHit(line);
        if (ref && (param !== null || OWNER_PROP_RE.test(line) || (loadedRe !== null && loadedRe.test(line)))) {
          const tenant = TENANT_RE.test(line);
          pushCheck(
            tenant ? 'tenant_comparison' : 'owner_comparison',
            param ?? '*',
            ref[0],
            i,
            rejects ? 'high' : 'medium',
            `Handler compares the authenticated identity "${ref[0]}" with ${tenant ? 'a tenant' : 'a resource owner'} value${rejects ? ' and rejects on mismatch' : ''}.`
          );
        }
      }

      for (const m of line.matchAll(POLICY_CALL_RE)) {
        const prefix = (m[1] ?? '').replace(/\s+/g, '').replace(/\.$/, '');
        const callee = m[2] ?? '';
        const args = m[3] ?? '';
        const onIdentity = prefix !== '' && idNames.some((n) => prefix === n || prefix.startsWith(`${n}.`));
        const withIdentity = refRe !== null && refRe.test(args);
        const objectPolicy = /^(?:check_object_permissions|has_object_permission)$/.test(callee);
        if (!onIdentity && !withIdentity && !objectPolicy) continue;
        pushCheck('policy_call', aliasHit(line) ?? '*', prefix === '' ? callee : `${prefix}.${callee}`, i, 'medium', `Handler delegates a resource-level decision to ${callee}().`);
      }
    }
  }
  return { resourceParameters, loads, checks };
}
