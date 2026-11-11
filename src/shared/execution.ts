/** Process capability; never grants target access, approval, or budget. */
export type ExecutionMode = "inspect" | "serve" | "execute";
export type ExecutionPolicy = { mode: ExecutionMode; source: "default" | "config" | "environment" };
export function executionPolicy(raw: unknown, env = process.env.NIANYUN_MODE): ExecutionPolicy {
  if (raw !== undefined && typeof raw !== "string") throw new Error("invalid execution.mode");
  const valid = (value: string): ExecutionMode => {
    if (!["inspect", "serve", "execute"].includes(value)) throw new Error("invalid execution.mode");
    return value as ExecutionMode;
  };
  const configured = raw === undefined ? undefined : valid(raw as string);
  const environment = env === undefined ? undefined : valid(env);
  if (configured && environment && configured !== environment) throw new Error("execution mode conflict");
  return { mode: environment || configured || "serve", source: environment ? "environment" : configured ? "config" : "default" };
}
export class ExecutionDenied extends Error {
  readonly code = "execution_disabled";
  constructor(action: string) { super(`execution_disabled: ${action} requires explicit execute mode`); }
}
export function requireExecution(cfg: { execution?: ExecutionPolicy }, action: string): void {
  if (cfg.execution?.mode !== "execute") throw new ExecutionDenied(action);
}
export function canExecute(cfg: { execution?: ExecutionPolicy }): boolean { return cfg.execution?.mode === "execute"; }
