declare module "node:sqlite" {
  export class DatabaseSync {
    constructor(path: string, options?: { readOnly?: boolean; timeout?: number });
    exec(sql: string): void;
    close(): void;
    prepare(sql: string): {
      run(...args: unknown[]): { changes?: number; lastInsertRowid?: number | bigint };
      get(...args: unknown[]): unknown;
      all(...args: unknown[]): unknown[];
    };
  }
}
