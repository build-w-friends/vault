import * as v from "valibot";
import {
  collectionContextSchema,
  collectionReceiptSchema,
} from "../collection-contract.ts";

const form = document.querySelector<HTMLFormElement>("#form")!;
const input = document.querySelector<HTMLInputElement>("#value")!;
const save = document.querySelector<HTMLButtonElement>("#save")!;
const cancel = document.querySelector<HTMLButtonElement>("#cancel")!;
const status = document.querySelector<HTMLElement>("#status")!;
let terminal = false;
// Set by any edit, even one that is later erased, so discarding input always asks first.
let dirty = false;
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
function clear() {
  terminal = true;
  input.value = "";
  dirty = false;
}
function show(receipt: v.InferOutput<typeof collectionReceiptSchema>) {
  status.textContent = messages[receipt.state];
  terminal = receipt.state !== "waiting" && receipt.state !== "saving";
  input.disabled = receipt.state !== "waiting";
  save.disabled = receipt.state !== "waiting";
  cancel.disabled = receipt.state !== "waiting";
  if (terminal) clear();
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
input.addEventListener("input", () => {
  dirty = true;
});
// The input's `required` and `maxlength` attributes enforce the 1–16384 character
// rule: the browser fires submit only when they pass.
form.addEventListener("submit", (event) => {
  event.preventDefault();
  if (terminal) return;
  const value = input.value;
  input.disabled = true;
  save.disabled = true;
  cancel.disabled = true;
  status.textContent = messages.saving;
  void post("submit", { value }).catch(() => {
    clear();
    status.textContent = messages.unknown;
  });
});
cancel.addEventListener("click", () => {
  if (dirty && !confirm("Discard the entered value and cancel?")) return;
  void post("cancel", {}).catch(() => {
    status.textContent =
      "Could not confirm cancellation. Close this page; the request will expire.";
  });
});
window.addEventListener("beforeunload", (event) => {
  if (!terminal && dirty) event.preventDefault();
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
