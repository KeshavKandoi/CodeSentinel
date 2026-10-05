import ts from 'typescript';
import { createAdapterContext } from '../../routes/sourceIndex.js';
import { contextFor, makeFinding, redactSecurityText } from '../utils.js';
import type { SecurityFinding, SecurityRule } from '../types.js';

function walk(node: ts.Node, visit: (node: ts.Node) => void): void {
  visit(node);
  ts.forEachChild(node, child => walk(child, visit));
}

function requestField(node: ts.Node): boolean {
  return ts.isPropertyAccessExpression(node) && /^(?:req|request)\.(?:body|query|params|headers)\.[A-Za-z_$][\w$]*$/.test(node.getText());
}

function enclosingFunction(node: ts.Node): ts.FunctionLikeDeclaration | null {
  for (let parent = node.parent; parent; parent = parent.parent) {
    if (ts.isArrowFunction(parent) || ts.isFunctionExpression(parent) || ts.isFunctionDeclaration(parent) || ts.isMethodDeclaration(parent)) return parent;
  }
  return null;
}

function childProcessNames(source: ts.SourceFile): Set<string> {
  const names = new Set<string>();
  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement) || !/^["'](?:node:)?child_process["']$/.test(statement.moduleSpecifier.getText())) continue;
    const bindings = statement.importClause?.namedBindings;
    if (bindings && ts.isNamedImports(bindings)) for (const element of bindings.elements) {
      if ((element.propertyName?.text ?? element.name.text) === 'exec' || (element.propertyName?.text ?? element.name.text) === 'execSync') names.add(element.name.text);
    }
  }
  return names;
}

export const commandFlowRule: SecurityRule = {
  id: 'CS-NODE-025', category: 'command_injection', title: 'Request-derived command reaches shell execution',
  description: 'A request field is assigned to a local command variable and then passed to a shell-executing child_process API. An attacker may control the executed command.',
  impact: 'An attacker may execute shell commands with the server process privileges.',
  severity: 'high', confidence: 'medium',
  evidenceRequirements: 'A request body, query, parameter, or header field flows through a local variable into child_process.exec or execSync.',
  remediation: 'Use a fixed executable with argument arrays and shell interpretation disabled; allowlist any selected operation.',
  falsePositiveGuidance: 'Custom validation outside the analyzed function may restrict the request field.', languages: ['node'],
  async run(context) {
    const warnings: string[] = [];
    const index = createAdapterContext(context.config, context.profile, warnings);
    const findings: SecurityFinding[] = [];
    for (const file of index.listSourceFiles(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'])) {
      const source = index.readSource(file);
      if (!source) continue;
      const ast = ts.createSourceFile(file, source.content, ts.ScriptTarget.Latest, true, /\.tsx?$/.test(file) ? ts.ScriptKind.TS : ts.ScriptKind.JS);
      if ((ast as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics?.length) continue;
      const shellNames = childProcessNames(ast);
      if (!shellNames.size) continue;
      walk(ast, node => {
        if (!ts.isCallExpression(node) || !ts.isIdentifier(node.expression) || !shellNames.has(node.expression.text)) return;
        const argument = node.arguments[0];
        if (!argument || !ts.isIdentifier(argument)) return;
        const scope = enclosingFunction(node);
        if (!scope || !scope.parameters.some(parameter => ts.isIdentifier(parameter.name) && /^(?:req|request)$/.test(parameter.name.text))) return;
        let sourceDeclaration: ts.VariableDeclaration | null = null;
        walk(scope.body ?? scope, candidate => {
          if (!ts.isVariableDeclaration(candidate) || !ts.isIdentifier(candidate.name) || candidate.name.text !== argument.text || candidate.getStart() >= node.getStart() || !candidate.initializer) return;
          if (enclosingFunction(candidate) !== scope) return;
          if (requestField(candidate.initializer)) sourceDeclaration = candidate;
        });
        if (!sourceDeclaration) return;
        const sinkLine = ast.getLineAndCharacterOfPosition(node.getStart(ast)).line + 1;
        const sourceLine = ast.getLineAndCharacterOfPosition((sourceDeclaration as ts.VariableDeclaration).getStart(ast)).line + 1;
        const finding = makeFinding(commandFlowRule, { file, line: sinkLine, matchedText: source.content.split('\n')[sinkLine - 1]?.trim().slice(0, 240), context: contextFor(source.content, sinkLine), reason: `Request-derived ${argument.text} is passed to shell execution; source at ${file}:${sourceLine}.` });
        finding.evidence.push({ file, line: sourceLine, matchedText: redactSecurityText(source.content.split('\n')[sourceLine - 1]?.trim().slice(0, 240) ?? ''), reason: 'The command variable is assigned from an incoming request field.' });
        findings.push(finding);
      });
    }
    for (const warning of warnings) context.warn(warning);
    return findings;
  },
};
