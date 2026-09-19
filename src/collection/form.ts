import { FormApi } from "@tanstack/form-core";
import * as v from "valibot";
import {
  collectionContextSchema,
  collectionReceiptSchema,
} from "../collection-contract.ts";

const input = document.querySelector<HTMLInputElement>("#value")!;
const save = document.querySelector<HTMLButtonElement>("#save")!;
const cancel = document.querySelector<HTMLButtonElement>("#cancel")!;
const status = document.querySelector<HTMLElement>("#status")!;
let terminal = false;
const messages = {
  waiting: "Ready. The request expires after ten minutes.",
  saving: "Saving to Vault…",
  stored: "Secret saved. You can close this page and return to your agent.",
  cancelled: "Cancelled. No secret was submitted.",
  expired: "This request expired. Ask your agent to start a new request.",
  conflict: "A secret with this name already exists. Its value was not changed.",
  unknown:
    "The save result could not be confirmed. Do not submit again. Ask your agent to inspect Vault before continuing.",
};
function show(receipt: v.InferOutput<typeof collectionReceiptSchema>) {
  status.textContent = messages[receipt.state];
  terminal = receipt.state !== "waiting" && receipt.state !== "saving";
  input.disabled = receipt.state !== "waiting";
  save.disabled = receipt.state !== "waiting";
  cancel.disabled = receipt.state !== "waiting";
  if (terminal) {
    input.value = "";
    form.reset();
  }
}
async function post(action: string, body: { value?: string }) {
  const response = await fetch(`${location.pathname}/${action}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error("Collection failed");
  show(v.parse(collectionReceiptSchema, await response.json()));
}
const form = new FormApi({
  defaultValues: { value: "" },
  validators: {
    onSubmit: v.object({ value: v.pipe(v.string(), v.minLength(1), v.maxLength(16384)) }),
  },
  onSubmit: async ({ value }) => {
    input.disabled = true;
    save.disabled = true;
    cancel.disabled = true;
    status.textContent = messages.saving;
    try {
      await post("submit", value);
    } catch {
      terminal = true;
      input.value = "";
      form.reset();
      status.textContent = messages.unknown;
    }
  },
});
form.mount();
input.addEventListener("input", () => {
  form.setFieldValue("value", input.value);
});
document.querySelector<HTMLFormElement>("#form")!.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!terminal) void form.handleSubmit();
});
cancel.addEventListener("click", () => {
  if (form.state.isDirty && !confirm("Discard the entered value and cancel?")) return;
  void post("cancel", {}).catch(() => {
    status.textContent =
      "Could not confirm cancellation. Close this page; the request will expire.";
  });
});
window.addEventListener("beforeunload", (event) => {
  if (!terminal && (form.state.isDirty || form.state.isSubmitting))
    event.preventDefault();
});
async function load() {
  const response = await fetch(`${location.pathname}/context`);
  const context = v.parse(collectionContextSchema, await response.json());
  const target = context.receipt.target;
  const destination = document.querySelector("#destination")!;
  for (const [label, value] of Object.entries({
    Vault: context.vaultOrigin,
    Project: target.project,
    Environment: target.env,
    Name: target.name,
    Kind: target.kind,
  })) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value;
    destination.append(dt, dd);
  }
  show(context.receipt);
}
void load().catch(() => {
  status.textContent = "This request is no longer available. Return to your agent.";
});
