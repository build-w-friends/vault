export class TemporaryConnectionError extends Error {
  override readonly name = "TemporaryConnectionError";
}

const DEFAULT_DEVICE_POLL_CLOCK = { now: () => Date.now(), wait: () => Bun.sleep(5000) };

export async function retryDevicePoll<T>(
  poll: () => Promise<T>,
  deadline: number,
  clock = DEFAULT_DEVICE_POLL_CLOCK,
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
