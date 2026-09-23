import type { DetectedItem, Evidence } from '../types.js';
import { fileExists, dirExists } from '../manifestReader.js';
import { hasDep, depVersion, type NodeAnalysisContext } from './context.js';

interface DepOnlySpec {
  name: string;
  depNames: string[];
  extraCheck?: (root: string) => Evidence | null;
}

const DATABASE_SPECS: DepOnlySpec[] = [
  { name: 'PostgreSQL', depNames: ['pg', 'postgres'] },
  { name: 'MySQL', depNames: ['mysql', 'mysql2'] },
  { name: 'MongoDB', depNames: ['mongodb', 'mongoose'] },
  { name: 'SQLite', depNames: ['sqlite3', 'better-sqlite3'] },
  { name: 'Redis', depNames: ['redis', 'ioredis'] },
];

const ORM_SPECS: DepOnlySpec[] = [
  {
    name: 'Prisma',
    depNames: ['@prisma/client', 'prisma'],
    extraCheck: (root) =>
      dirExists(root, 'prisma') || fileExists(root, 'prisma/schema.prisma')
        ? { source: 'file:prisma/schema.prisma', detail: 'prisma/ directory or schema.prisma found' }
        : null,
  },
  { name: 'TypeORM', depNames: ['typeorm'] },
  { name: 'Sequelize', depNames: ['sequelize'] },
  { name: 'Mongoose', depNames: ['mongoose'] },
  { name: 'Drizzle', depNames: ['drizzle-orm'] },
];

function detectDepOnlySpecs(root: string, ctx: NodeAnalysisContext, specs: DepOnlySpec[]): DetectedItem[] {
  const results: DetectedItem[] = [];
  for (const spec of specs) {
    const matchedDep = spec.depNames.find((d) => hasDep(ctx, d));
    if (!matchedDep) continue;

    const evidence: Evidence[] = [
      {
        source: 'package.json dependencies',
        detail: `"${matchedDep}"${depVersion(ctx, matchedDep) ? ` (${depVersion(ctx, matchedDep)})` : ''} listed as a dependency`,
      },
    ];
    let confidence: 'high' | 'medium' = 'medium';
    if (spec.extraCheck) {
      const extra = spec.extraCheck(root);
      if (extra) {
        evidence.push(extra);
        confidence = 'high';
      }
    }
    results.push({ name: spec.name, confidence, evidence });
  }
  return results;
}

export function detectDatabases(root: string, ctx: NodeAnalysisContext): DetectedItem[] {
  return detectDepOnlySpecs(root, ctx, DATABASE_SPECS);
}

export function detectOrms(root: string, ctx: NodeAnalysisContext): DetectedItem[] {
  return detectDepOnlySpecs(root, ctx, ORM_SPECS);
}
