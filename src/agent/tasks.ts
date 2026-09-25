import { Database } from "bun:sqlite";
import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import * as v from "valibot";

const taskSchema = v.object({
  taskId: v.pipe(v.string(), v.uuid()),
  requestId: v.pipe(v.string(), v.uuid()),
  ownerPid: v.number(),
  kind: v.picklist(["collection", "cloudflare", "github"]),
  target: v.string(),
  state: v.picklist([
    "waiting",
    "saving",
    "stored",
    "cancelled",
    "expired",
    "conflict",
    "unknown",
  ]),
  createdAt: v.number(),
  updatedAt: v.number(),
  expiresAt: v.number(),
  url: v.nullable(v.string()),
});
export type AgentTask = v.InferOutput<typeof taskSchema>;
/** Only request metadata is persisted here. Provider values belong in Vault. */
export class AgentTasks {
  private readonly db: Database;
  constructor(
    path: string,
    private readonly now = Date.now,
  ) {
    if (path !== ":memory:") {
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      chmodSync(dirname(path), 0o700);
    }
    this.db = new Database(path, { create: true });
    if (path !== ":memory:") chmodSync(path, 0o600);
    this.db.exec(
      "PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, record TEXT NOT NULL)",
    );
  }
  create(requestId: string, kind: AgentTask["kind"], target: string) {
    const now = this.now();
    const record = v.parse(taskSchema, {
      taskId: crypto.randomUUID(),
      requestId,
      ownerPid: process.pid,
      kind,
      target,
      state: "waiting",
      createdAt: now,
      updatedAt: now,
      expiresAt: now + 600000,
      url: null,
    });
    const change = this.db
      .query("INSERT OR IGNORE INTO tasks VALUES (?, ?, ?)")
      .run(record.taskId, requestId, JSON.stringify(record));
    const task = this.get(requestId);
    if (task.kind !== kind || task.target !== target)
      throw new Error("Request ID is already bound to another operation");
    return { task, created: change.changes === 1 };
  }
  /** Reads a task by task ID or request ID, with the stored record for compare-and-set. */
  private row(taskId: string) {
    const row = this.db
      .query<{ record: string }, [string, string]>(
        "SELECT record FROM tasks WHERE id = ? OR request_id = ?",
      )
      .get(taskId, taskId);
    if (!row) throw new Error("Task not found");
    return { record: row.record, task: v.parse(taskSchema, JSON.parse(row.record)) };
  }
  /** Replaces the record only if it still equals `record`; true when it did. */
  private swap(record: string, next: AgentTask) {
    return (
      this.db
        .query("UPDATE tasks SET record = ? WHERE id = ? AND record = ?")
        .run(JSON.stringify(next), next.taskId, record).changes === 1
    );
  }
  get(taskId: string): AgentTask {
    const { task } = this.row(taskId);
    if (
      (task.state === "waiting" || task.state === "saving") &&
      task.expiresAt <= this.now()
    )
      return this.transition(
        taskId,
        task.state,
        task.state === "waiting" ? "expired" : "unknown",
      );
    return task;
  }
  transition(
    taskId: string,
    from: AgentTask["state"],
    to: AgentTask["state"],
    url: string | null = null,
  ): AgentTask {
    const { record, task } = this.row(taskId);
    if (task.state !== from) return task;
    this.swap(record, {
      ...task,
      state: to,
      url,
      updatedAt: this.now(),
      expiresAt: to === "saving" ? this.now() + 60000 : task.expiresAt,
    });
    return this.get(taskId);
  }
  claim(taskId: string): boolean {
    const task = this.get(taskId);
    if (task.state !== "waiting") return false;
    return this.swap(JSON.stringify(task), {
      ...task,
      state: "saving",
      url: null,
      updatedAt: this.now(),
      expiresAt: this.now() + 60000,
    });
  }
  release(taskId: string) {
    const task = this.get(taskId);
    if (task.state !== "waiting" || task.ownerPid !== process.pid) return;
    this.swap(JSON.stringify(task), { ...task, ownerPid: 0, url: null });
  }
  reclaim(taskId: string) {
    const task = this.get(taskId);
    if (task.state !== "waiting") return false;
    if (task.ownerPid !== 0) {
      try {
        process.kill(task.ownerPid, 0);
        return false;
      } catch (error) {
        if (!(error instanceof Error) || !("code" in error) || error.code !== "ESRCH")
          return false;
      }
    }
    return this.swap(JSON.stringify(task), { ...task, ownerPid: process.pid, url: null });
  }
  close() {
    this.db.close();
  }
}
