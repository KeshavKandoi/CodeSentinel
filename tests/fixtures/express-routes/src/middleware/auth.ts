export function authenticate(req: any, res: any, next: () => void) {
  next();
}

export function requireRole(role: string) {
  return (req: any, res: any, next: () => void) => next();
}
