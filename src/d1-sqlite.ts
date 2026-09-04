import { Database, type SQLQueryBindings } from "bun:sqlite";

type SqliteColumnValue = string | number | Uint8Array | null;
type SqliteRow = Record<string, SqliteColumnValue>;

function bindings(values: unknown[]): SQLQueryBindings[] {
  // SAFETY: this private adapter is called only by VaultStore and VaultKeyring;
  // their bind sites pass strings, numbers, or null, all valid SQLite bindings.
  return values as SQLQueryBindings[];
}

function emptyMeta(overrides: Partial<D1Meta> = {}) {
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
    if (colName != null) {
      const row = this.db
        .query<Record<string, T>, SQLQueryBindings[]>(this.query)
        .get(...bindings(this.values));
      return row?.[colName] ?? null;
    }
    return this.db.query<T, SQLQueryBindings[]>(this.query).get(...bindings(this.values));
  }

  async run<T = SqliteRow>(): Promise<D1Result<T>> {
    return this.runSync<T>();
  }

  runSync<T = SqliteRow>(): D1Result<T> {
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

  async all<T = SqliteRow>(): Promise<D1Result<T>> {
    const results = this.db
      .query<T, SQLQueryBindings[]>(this.query)
      .all(...bindings(this.values));
    return {
      success: true,
      meta: emptyMeta({ rows_read: results.length }),
      results,
    };
  }

  async raw<T = unknown[]>(options: { columnNames: true }): Promise<[string[], ...T[]]>;
  async raw<T = unknown[]>(options?: { columnNames?: false }): Promise<T[]>;
  async raw<T = unknown[]>(options?: {
    columnNames?: boolean;
  }): Promise<T[] | [string[], ...T[]]> {
    const rows = this.db
      .query<SqliteRow, SQLQueryBindings[]>(this.query)
      .all(...bindings(this.values));
    if (options?.columnNames === true) {
      const names = rows[0] != null ? Object.keys(rows[0]) : [];
      // SAFETY: callers supply T matching the selected row tuple; Object.values
      // preserves SQLite's column order for D1.raw's tuple contract.
      const values = rows.map((row) => Object.values(row)) as T[];
      return [names, ...values];
    }
    // SAFETY: callers supply T matching the selected row tuple; Object.values
    // preserves SQLite's column order for D1.raw's row-array contract.
    return rows.map((row) => Object.values(row)) as T[];
  }
}

function wrapSqliteAsD1(db: Database): D1Database {
  const adapter: D1Database = {
    prepare(query: string) {
      return new SqlitePreparedStatement(db, query, []);
    },
    async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
      return db.transaction(() =>
        statements.map((statement) => {
          if (!(statement instanceof SqlitePreparedStatement)) {
            throw new Error("sqlite D1 adapter received an unknown statement");
          }
          return statement.runSync<T>();
        }),
      )();
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
