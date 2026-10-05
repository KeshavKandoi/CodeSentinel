import ts from 'typescript';
import { createAdapterContext } from '../../routes/sourceIndex.js';
import { contextFor, makeFinding } from '../utils.js';
import type { SecurityFinding, SecurityRule, SecurityScanContext } from '../types.js';

const definitions = [
  { id: 'CS-NODE-022', category: 'authentication', title: 'Client-controlled WebSocket identity is trusted', description: 'An incoming WebSocket message supplies an identity used for connection registration. This can let a caller claim another user and affect message routing or attribution.', impact: 'A caller may claim another user identity and affect message routing or sender attribution.', severity: 'high', confidence: 'medium', evidenceRequirements: 'A field from a parsed WebSocket message reaches an identity registration call without a visible verification step.', remediation: 'Authenticate the connection and derive its user identity from a verified session or token before registration.', falsePositiveGuidance: 'Review external authentication or an identity check in a helper that static analysis cannot resolve.', languages: ['node'] },
  { id: 'CS-NODE-023', category: 'security_configuration', title: 'Operational metrics returned without a visible guard', description: 'An HTTP handler returns operational metrics before a visible authentication check. The data can reveal service activity and topology.', impact: 'An unauthenticated caller reaching this route may observe operational data and service topology.', severity: 'medium', confidence: 'medium', evidenceRequirements: 'A /metrics handler returns a runtime snapshot or metrics object without a visible guard in the handler.', remediation: 'Restrict the metrics route to authenticated operators or a private monitoring network.', falsePositiveGuidance: 'A reverse proxy or private network may restrict access outside the analyzed source.', languages: ['node'] },
  { id: 'CS-NODE-024', category: 'security_configuration', title: 'Large WebSocket messages reach sensitive processing', description: 'A WebSocket server processes incoming messages at a sensitive sink without an explicit payload bound. Large inputs may consume excessive resources.', impact: 'Large client messages may consume excess CPU or memory before sensitive processing completes.', severity: 'medium', confidence: 'low', evidenceRequirements: 'WebSocketServer lacks maxPayload while a message handler parses client data and passes it to an expensive or persistent operation.', remediation: 'Set an appropriate maxPayload and validate message size before expensive processing.', falsePositiveGuidance: 'A proxy, library default, or an equivalent limit outside the analyzed handler may bound messages.', languages: ['node'] },
] as const;

type Definition = (typeof definitions)[number];
function children(node: ts.Node, predicate: (node: ts.Node) => boolean): ts.Node[] {
  const found: ts.Node[] = [];
  const visit = (child: ts.Node): void => { if (predicate(child)) found.push(child); ts.forEachChild(child, visit); };
  visit(node);
  return found;
}
function callName(node: ts.Node): string { return ts.isCallExpression(node) ? node.expression.getText() : ''; }
function callbackFor(node: ts.CallExpression, event: string): ts.FunctionExpression | ts.ArrowFunction | null {
  if (!/\.on$/.test(callName(node)) || node.arguments[0]?.getText().replaceAll(/["'`]/g, '') !== event) return null;
  const callback = node.arguments[1];
  return callback && (ts.isArrowFunction(callback) || ts.isFunctionExpression(callback)) ? callback : null;
}
function isClientIdentity(text: string, parsedNames: Set<string>): boolean {
  return [...parsedNames].some(name => new RegExp(`\\b${name}\\s*(?:\\.|\\[)\\s*["']?(?:userId|username|accountId)["']?\\b`).test(text));
}

function inspect(source: ts.SourceFile, definition: Definition): ts.Node[] {
  const calls = children(source, ts.isCallExpression) as ts.CallExpression[];
  if (definition.id === 'CS-NODE-022') {
    const hits: ts.Node[] = [];
    for (const messageOn of calls) {
      const callback = callbackFor(messageOn, 'message');
      if (!callback) continue;
      const parsedNames = new Set<string>();
      for (const declaration of children(callback, ts.isVariableDeclaration) as ts.VariableDeclaration[]) {
        if (ts.isIdentifier(declaration.name) && declaration.initializer && /JSON\.parse\s*\(/.test(declaration.initializer.getText())) parsedNames.add(declaration.name.text);
      }
      for (const assignment of children(callback, ts.isBinaryExpression) as ts.BinaryExpression[]) {
        if (assignment.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(assignment.left) && /JSON\.parse\s*\(/.test(assignment.right.getText())) parsedNames.add(assignment.left.text);
      }
      for (const declaration of children(callback, ts.isVariableDeclaration) as ts.VariableDeclaration[]) {
        if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
        const expression = declaration.initializer.getText();
        if ([...parsedNames].some(name => new RegExp(`^${name}\\b`).test(expression))) parsedNames.add(declaration.name.text);
      }
      if (!parsedNames.size) continue;
      for (const sink of children(callback, ts.isCallExpression) as ts.CallExpression[]) {
        if (!/\.(?:registerUser|registerIdentity|register|identify|bindUser)$/.test(callName(sink))) continue;
        if (!sink.arguments.some(argument => isClientIdentity(argument.getText(), parsedNames))) continue;
        hits.push(sink);
      }
    }
    return hits;
  }
  if (definition.id === 'CS-NODE-023') {
    const hits: ts.Node[] = [];
    for (const conditional of children(source, ts.isIfStatement) as ts.IfStatement[]) {
      if (!/req(?:uest)?\.url\s*===?\s*["']\/metrics["']/.test(conditional.expression.getText())) continue;
      const body = conditional.thenStatement.getText();
      if (!/res\.(?:end|send|json)\s*\(/.test(body) || !/(?:snapshot|metrics|active_connections|bytes_received|registry)/i.test(body)) continue;
      if (/\b(?:authenticate|authorize|requireAuth|verifyToken|isAuthenticated)\s*\(/i.test(body)) continue;
      hits.push(conditional);
    }
    return hits;
  }
  const servers = children(source, ts.isNewExpression) as ts.NewExpression[];
  const sensitiveMessage = calls.some(call => {
    const callback = callbackFor(call, 'message');
    if (!callback) return false;
    const body = callback.getText();
    const sizeGuard = /(?:byteLength|\.length)\s*>\s*(?:\d|[A-Z_]*MAX|[A-Z_]*LIMIT)/.test(body) && /\b(?:return|close|terminate|throw)\b/.test(body);
    return !sizeGuard && /JSON\.parse\s*\(/.test(body) && /\b(?:save|insert|publish|writeFile|query|registerUser)\s*\(/.test(body);
  });
  return sensitiveMessage ? servers.filter(server => /(?:^|\.)WebSocketServer$/.test(server.expression.getText()) && !/\bmaxPayload\s*:/.test(server.getText())) : [];
}

function rule(definition: Definition): SecurityRule {
  const result: SecurityRule = {
    ...definition,
    languages: [...definition.languages],
    async run(context: SecurityScanContext): Promise<SecurityFinding[]> {
      const warnings: string[] = [];
      const index = createAdapterContext(context.config, context.profile, warnings);
      const findings: SecurityFinding[] = [];
      for (const file of index.listSourceFiles(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'])) {
        const source = index.readSource(file);
        if (!source) continue;
        const kind = /\.tsx?$/.test(file) ? ts.ScriptKind.TS : ts.ScriptKind.JS;
        const ast = ts.createSourceFile(file, source.content, ts.ScriptTarget.Latest, true, kind);
        if ((ast as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics?.length) {
          warnings.push(`Skipped malformed source for AST analysis: ${file}.`);
          continue;
        }
        context.recordFile(file);
        for (const node of inspect(ast, definition)) {
          const line = ast.getLineAndCharacterOfPosition(node.getStart(ast)).line + 1;
          findings.push(makeFinding(result, { file, line, matchedText: source.content.split('\n')[line - 1]?.trim().slice(0, 240), context: contextFor(source.content, line), reason: definition.evidenceRequirements }));
        }
      }
      for (const warning of warnings) context.warn(warning);
      return findings;
    },
  };
  return result;
}
export const semanticNodeRules: SecurityRule[] = definitions.map(rule);
