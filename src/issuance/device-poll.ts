export class TemporaryConnectionError extends Error {}

export async function retryDevicePoll<T>(
  poll: () => Promise<T>,
  deadline: number,
  clock = { now: () => Date.now(), wait: () => Bun.sleep(5000) },
): Promise<T> {
  while (clock.now() < deadline) {
    try {
      return await poll();
    } catch (error) {
      if (!(error instanceof TemporaryConnectionError)) throw error;
      await clock.wait();
    }
  }
  throw new Error("Vault connection expired; run issuance login again");
}
