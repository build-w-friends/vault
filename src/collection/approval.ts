import { FormApi } from "@tanstack/form-core";
import * as v from "valibot";
import { collectionStateSchema } from "../collection-contract.ts";
const element = document.querySelector<HTMLFormElement>("#approval")!;
const buttons = element.querySelectorAll<HTMLButtonElement>("button");
const status = document.querySelector<HTMLElement>("#result")!;
const form = new FormApi({
  defaultValues: { decision: "cancel" },
  validators: { onSubmit: v.object({ decision: v.picklist(["approve", "cancel"]) }) },
  onSubmit: async ({ value }) => {
    for (const button of buttons) button.disabled = true;
    status.textContent = "Saving your decision…";
    try {
      const response = await fetch(location.pathname, {
        method: "POST",
        headers: { Accept: "application/json" },
        body: new URLSearchParams(value),
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
  },
});
form.mount();
for (const button of buttons) button.disabled = false;
element.addEventListener("submit", (event) => {
  event.preventDefault();
  const submitter = event.submitter;
  if (!(submitter instanceof HTMLButtonElement)) return;
  form.setFieldValue("decision", submitter.value);
  void form.handleSubmit();
});
