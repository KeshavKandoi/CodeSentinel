/** Result envelope every tool implementation returns internally, before
 * being adapted into the MCP tool response format. */
export interface ToolResult<T> {
  ok: true;
  data: T;
}

export interface ToolError {
  ok: false;
  error: {
    code: ToolErrorCode;
    message: string;
  };
}

export type ToolOutcome<T> = ToolResult<T> | ToolError;

export type ToolErrorCode =
  | 'INVALID_INPUT'
  | 'PATH_OUTSIDE_ROOT'
  | 'NOT_FOUND'
  | 'NOT_A_FILE'
  | 'NOT_A_DIRECTORY'
  | 'FILE_TOO_LARGE'
  | 'COMMAND_NOT_ALLOWED'
  | 'COMMAND_TIMEOUT'
  | 'COMMAND_FAILED'
  | 'TARGET_BLOCKED'
  | 'UNSUPPORTED_CANDIDATE_TYPE'
  | 'PROJECT_BOUNDARY'
  | 'INVESTIGATION_NOT_FOUND'
  | 'HYPOTHESIS_NOT_FOUND'
  | 'HYPOTHESIS_INVALID'
  | 'INVALID_TRANSITION'
  | 'DUPLICATE_OPERATION'
  | 'BUDGET_EXCEEDED'
  | 'ANALYSIS_FAILED'
  | 'INVESTIGATION_INCOMPLETE'
  | 'REPORT_FINDING_NOT_FOUND'
  | 'REPORT_INVALID'
  | 'INTERNAL_ERROR';

export function ok<T>(data: T): ToolOutcome<T> {
  return { ok: true, data };
}

export function err<T>(code: ToolErrorCode, message: string): ToolOutcome<T> {
  return { ok: false, error: { code, message } };
}

export interface FileEntry {
  path: string; // relative to project root, POSIX-style separators
  type: 'file' | 'directory';
  sizeBytes?: number;
}

export interface SearchMatch {
  path: string;
  line: number;
  column: number;
  preview: string;
}

export interface CommandResult {
  command: string;
  args: string[];
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  timedOut: boolean;
  durationMs: number;
}
