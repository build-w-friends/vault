import * as v from "valibot";
import { collectionStateSchema } from "../collection-contract.ts";
const element = document.querySelector<HTMLFormElement>("#approval")!;
const buttons = element.querySelectorAll<HTMLButtonElement>("button");
const status = document.querySelector<HTMLElement>("#result")!;
async function decide(decision: string) {
  for (const button of buttons) button.disabled = true;
  status.textContent = "Saving your decision…";
  try {
    const response = await fetch(location.pathname, {
      method: "POST",
      headers: { Accept: "application/json" },
      body: new URLSearchParams({ decision }),
    });
    if (!response.ok) throw new Error("Decision failed");
    const receipt = v.parse(
      v.object({ state: collectionStateSchema }),
      await response.json(),
    );
    status.textContent = `${receipt.state}. Return to your agent.`;
  } catch {
    status.textContent =
      "The result could not be confirmed. Ask your agent to inspect the request before continuing.";
  }
}
for (const button of buttons) button.disabled = false;
element.addEventListener("submit", (event) => {
  event.preventDefault();
  // The clicked button's value is the decision: approve or cancel.
  if (event.submitter instanceof HTMLButtonElement) void decide(event.submitter.value);
});
