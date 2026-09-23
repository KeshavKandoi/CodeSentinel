import type { DetectedItem, Evidence } from '../types.js';
import { fileExists } from '../manifestReader.js';
import type { NodeAnalysisContext } from './context.js';

export function detectLanguages(root: string, ctx: NodeAnalysisContext): DetectedItem[] {
  const languages: DetectedItem[] = [];

  const tsConfigExists = fileExists(root, 'tsconfig.json');
  const hasTsDep = !!(ctx.pkg && (
    (ctx.pkg.devDependencies && ctx.pkg.devDependencies.typescript) ||
    (ctx.pkg.dependencies && ctx.pkg.dependencies.typescript)
  ));

  if (tsConfigExists) {
    const evidence: Evidence[] = [{ source: 'file:tsconfig.json', detail: 'tsconfig.json is present' }];
    if (hasTsDep) evidence.push({ source: 'package.json dependencies', detail: '"typescript" listed as a dependency' });
    languages.push({ name: 'TypeScript', confidence: 'high', evidence });
  } else if (hasTsDep) {
    languages.push({
      name: 'TypeScript',
      confidence: 'medium',
      evidence: [{ source: 'package.json dependencies', detail: '"typescript" listed as a dependency, but no tsconfig.json found' }],
    });
  }

  // Based on file existence, not successful parse: a malformed package.json
  // is still strong evidence this is a JS/Node project.
  if (fileExists(root, 'package.json')) {
    languages.push({
      name: 'JavaScript',
      confidence: 'high',
      evidence: [{ source: 'file:package.json', detail: 'package.json is present, indicating a Node.js/JavaScript project' }],
    });
  }

  return languages;
}
