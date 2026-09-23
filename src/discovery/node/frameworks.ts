import type { DetectedItem, Evidence } from '../types.js';
import { fileExists, readTextFile } from '../manifestReader.js';
import { hasDep, depVersion, type NodeAnalysisContext } from './context.js';

/**
 * Framework detection is deliberately conservative: a dependency name
 * alone is treated as medium confidence, and confidence is raised to high
 * only when corroborated by a framework-specific config file or a
 * source-code import/require of that exact package. This avoids false
 * positives from, e.g., a file merely named "next.config.js.bak" or a
 * project that lists a framework as an unused transitive dependency.
 */

interface FrameworkSpec {
  name: string;
  depNames: string[];
  configFiles: string[];
  /** Regexes checked against a handful of likely source files; a match
   * raises confidence from medium (dep-only) to high. */
  sourcePatterns: RegExp[];
}

const BACKEND_SPECS: FrameworkSpec[] = [
  {
    name: 'NestJS',
    depNames: ['@nestjs/core', '@nestjs/common'],
    configFiles: ['nest-cli.json'],
    sourcePatterns: [/from\s+['"]@nestjs\/common['"]/, /require\(['"]@nestjs\/common['"]\)/, /@Module\s*\(/],
  },
  {
    name: 'Express',
    depNames: ['express'],
    configFiles: [],
    sourcePatterns: [/from\s+['"]express['"]/, /require\(['"]express['"]\)/, /express\(\)/],
  },
  {
    name: 'Fastify',
    depNames: ['fastify'],
    configFiles: [],
    sourcePatterns: [/from\s+['"]fastify['"]/, /require\(['"]fastify['"]\)/],
  },
  {
    name: 'Koa',
    depNames: ['koa'],
    configFiles: [],
    sourcePatterns: [/from\s+['"]koa['"]/, /require\(['"]koa['"]\)/],
  },
];

const FRONTEND_SPECS: FrameworkSpec[] = [
  {
    name: 'Next.js',
    depNames: ['next'],
    configFiles: ['next.config.js', 'next.config.mjs', 'next.config.ts'],
    sourcePatterns: [/from\s+['"]next['"]/, /require\(['"]next['"]\)/],
  },
  {
    name: 'React',
    depNames: ['react', 'react-dom'],
    configFiles: [],
    sourcePatterns: [/from\s+['"]react['"]/, /require\(['"]react['"]\)/],
  },
  {
    name: 'Vue',
    depNames: ['vue'],
    configFiles: ['vue.config.js'],
    sourcePatterns: [/from\s+['"]vue['"]/, /require\(['"]vue['"]\)/],
  },
  {
    name: 'Angular',
    depNames: ['@angular/core'],
    configFiles: ['angular.json'],
    sourcePatterns: [/from\s+['"]@angular\/core['"]/],
  },
];

/** A handful of likely-entry-point files checked for import/require
 * evidence, kept small and deterministic rather than scanning the whole
 * tree (that is search_files's job, not discovery's). */
const LIKELY_SOURCE_FILES = [
  'index.js',
  'index.ts',
  'src/index.js',
  'src/index.ts',
  'src/main.ts',
  'src/main.js',
  'src/app.js',
  'src/app.ts',
  'app.js',
  'app.ts',
  'server.js',
  'server.ts',
  'pages/_app.js',
  'pages/_app.tsx',
  'src/pages/_app.tsx',
];

function detectSpec(root: string, ctx: NodeAnalysisContext, spec: FrameworkSpec): DetectedItem | null {
  const matchedDep = spec.depNames.find((d) => hasDep(ctx, d));
  const matchedConfig = spec.configFiles.find((f) => fileExists(root, f));

  // A dependency listing is the required, authoritative signal. A config
  // file with a matching name is only ever corroborating evidence — on its
  // own it must NOT trigger detection, since a leftover/unrelated file
  // (e.g. a stray next.config.js in a non-Next.js project) is common and
  // must not produce a false positive.
  if (!matchedDep) return null;

  const evidence: Evidence[] = [
    {
      source: 'package.json dependencies',
      detail: `"${matchedDep}"${depVersion(ctx, matchedDep) ? ` (${depVersion(ctx, matchedDep)})` : ''} listed as a dependency`,
    },
  ];
  if (matchedConfig) {
    evidence.push({ source: `file:${matchedConfig}`, detail: `${matchedConfig} is present` });
  }

  let sourceMatchFile: string | null = null;
  for (const relFile of LIKELY_SOURCE_FILES) {
    const text = readTextFile(root, relFile);
    if (!text) continue;
    if (spec.sourcePatterns.some((re) => re.test(text))) {
      sourceMatchFile = relFile;
      break;
    }
  }
  if (sourceMatchFile) {
    evidence.push({ source: `content-match:${sourceMatchFile}`, detail: `Import/usage pattern for ${spec.name} found` });
  }

  // Dependency presence alone is medium confidence. High confidence
  // requires the dependency to be corroborated by a matching config file
  // and/or an actual import/usage pattern in a likely source file.
  const corroborated = Boolean(matchedConfig) || Boolean(sourceMatchFile);
  const confidence = corroborated ? 'high' : 'medium';

  return { name: spec.name, confidence, evidence };
}

export function detectBackendFrameworks(root: string, ctx: NodeAnalysisContext): DetectedItem[] {
  return BACKEND_SPECS.map((spec) => detectSpec(root, ctx, spec)).filter((x): x is DetectedItem => x !== null);
}

export function detectFrontendFrameworks(root: string, ctx: NodeAnalysisContext): DetectedItem[] {
  return FRONTEND_SPECS.map((spec) => detectSpec(root, ctx, spec)).filter((x): x is DetectedItem => x !== null);
}
