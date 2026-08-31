import { Database, type SQLQueryBindings } from "bun:sqlite";

function bindings(values: unknown[]): SQLQueryBindings[] {
  return values as SQLQueryBindings[];
}

function emptyMeta(overrides: Partial<D1Meta> = {}): D1Meta {
  return {
    duration: 0,
    size_after: 0,
    rows_read: 0,
    rows_written: 0,
    last_row_id: 0,
    changed_db: false,
    changes: 0,
    ...overrides,
  };
}

class SqlitePreparedStatement implements D1PreparedStatement {
  constructor(
    private readonly db: Database,
    private readonly query: string,
    private readonly values: unknown[],
  ) {}

  bind(...values: unknown[]): D1PreparedStatement {
    return new SqlitePreparedStatement(this.db, this.query, values);
  }

  async first<T = unknown>(colName?: string): Promise<T | null> {
    const row = this.db.query(this.query).get(...bindings(this.values)) as Record<
      string,
      unknown
    > | null;
    if (row == null) return null;
    if (colName != null) return (row[colName] as T) ?? null;
    return row as T;
  }

  async run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    const result = this.db.query(this.query).run(...bindings(this.values));
    return {
      success: true,
      meta: emptyMeta({
        rows_written: result.changes,
        last_row_id: Number(result.lastInsertRowid),
        changed_db: result.changes > 0,
        changes: result.changes,
      }),
      results: [],
    };
  }

  async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    const results = this.db.query(this.query).all(...bindings(this.values)) as T[];
    return {
      success: true,
      meta: emptyMeta({ rows_read: results.length }),
      results,
    };
  }

  async raw<T = unknown[]>(options?: {
    columnNames?: boolean;
  }): Promise<T[] | [string[], ...T[]]> {
    const rows = this.db.query(this.query).all(...bindings(this.values)) as Record<
      string,
      unknown
    >[];
    if (options?.columnNames === true) {
      const names = rows[0] != null ? Object.keys(rows[0]) : [];
      const values = rows.map((row) => Object.values(row)) as T[];
      return [names, ...values];
    }
    return rows.map((row) => Object.values(row)) as T[];
  }
}

export function wrapSqliteAsD1(db: Database): D1Database {
  const adapter: D1Database = {
    prepare(query: string) {
      return new SqlitePreparedStatement(db, query, []);
    },
    async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
      const results: D1Result<T>[] = [];
      for (const statement of statements) results.push(await statement.run<T>());
      return results;
    },
    async exec(query: string) {
      db.exec(query);
      return { count: 0, duration: 0 };
    },
    async dump() {
      throw new Error("D1 dump is not implemented in the sqlite test adapter");
    },
    withSession() {
      throw new Error("D1 sessions are not implemented in the sqlite test adapter");
    },
  };
  return adapter;
}

export function openMemoryD1(migrationSql: string): D1Database {
  const db = new Database(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  db.exec(migrationSql);
  return wrapSqliteAsD1(db);
}
