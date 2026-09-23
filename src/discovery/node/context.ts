export interface PackageJsonShape {
  name?: string;
  version?: string;
  main?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

export interface NodeAnalysisContext {
  root: string;
  pkg: PackageJsonShape | null;
  pkgWarning: string | null;
  /** dependencies + devDependencies merged into one lookup, tagged with
   * whether each came from devDependencies. dependencies wins on conflict. */
  allDeps: Record<string, { version: string; dev: boolean }>;
}

export function buildNodeContext(
  root: string,
  pkg: PackageJsonShape | null,
  pkgWarning: string | null
): NodeAnalysisContext {
  const allDeps: Record<string, { version: string; dev: boolean }> = {};
  if (pkg && pkg.dependencies) {
    for (const [name, version] of Object.entries(pkg.dependencies)) {
      allDeps[name] = { version, dev: false };
    }
  }
  if (pkg && pkg.devDependencies) {
    for (const [name, version] of Object.entries(pkg.devDependencies)) {
      if (!allDeps[name]) allDeps[name] = { version, dev: true };
    }
  }
  return { root, pkg, pkgWarning, allDeps };
}

export function hasDep(ctx: NodeAnalysisContext, name: string): boolean {
  return Object.prototype.hasOwnProperty.call(ctx.allDeps, name);
}

export function depVersion(ctx: NodeAnalysisContext, name: string): string | undefined {
  return ctx.allDeps[name]?.version;
}
