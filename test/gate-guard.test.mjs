import test from "node:test";
import assert from "node:assert/strict";
import { apply, Config } from "../lib/index.js";

// Tests the tool-level contract, not the engine (lib/protect.js is covered by
// protect.test.mjs). smoke-import.mjs asserts gate_guard is *registered*; these
// assert it is *reachable* — which is the half that was missing.
//
// Two layers have to be reproduced faithfully, or the drift hides:
//
//  1. defineTool() normalizes the `parameters` map (name -> schema) into a
//     single object schema, so the declared names live at
//     `tool.parameters.properties`. Declaring `input: { ... }` therefore creates
//     a real parameter literally NAMED "input" — which is how #5 shipped.
//  2. The host delivers only the arguments a tool declared, so a call must be
//     mapped through those names before it reaches `execute`.

function harness() {
  const tools = [];
  const ctx = {
    tools: { register: (t) => tools.push(t) },
    systemPrompt: { section: () => () => {} },
    effect: (fn) => fn(),
    fs: {},
  };
  apply(ctx, Config());
  return {
    tools,
    get(name) {
      const t = tools.find((x) => x.name === name);
      assert.ok(t, `tool ${name} is not registered`);
      return t;
    },
  };
}

/** Parameter names as the host sees them, after defineTool's normalization. */
function declared(tool) {
  return Object.keys(tool.parameters?.properties ?? {});
}

/** Reproduce the host's argument mapping: declared params only. */
function deliver(tool, call) {
  const args = {};
  for (const k of declared(tool)) if (k in call) args[k] = call[k];
  return args;
}

const exec = { agent: { session: { header: { cwd: "/home/dev/proj" } } } };

test("gate_guard declares command/path/action as direct parameters", () => {
  const { get } = harness();
  assert.deepEqual(declared(get("gate_guard")), ["command", "path", "action"]);
});

test("gate_guard reaches evaluateCommand through its declared parameters", async () => {
  const { get } = harness();
  const g = get("gate_guard");
  const run = (call) => g.execute(deliver(g, call), exec);

  assert.equal((await run({ command: "rm -rf /" })).verdict, "BLOCK");
  assert.equal((await run({ command: "mkfs.ext4 /dev/sdb1" })).verdict, "BLOCK");
  assert.equal((await run({ command: "rm -rf ./node_modules" })).verdict, "WARN");
  assert.equal((await run({ command: "npm run build" })).verdict, "PASS");
});

test("gate_guard reaches evaluatePath through its declared parameters", async () => {
  const { get } = harness();
  const g = get("gate_guard");
  const run = (call) => g.execute(deliver(g, call), exec);

  assert.equal((await run({ path: "/", action: "delete" })).verdict, "BLOCK");
  assert.equal((await run({ path: "/home/dev/proj/src/tmp", action: "delete" })).verdict, "WARN");
  assert.equal((await run({ path: "/home/dev/elsewhere", action: "delete" })).verdict, "WARN");
});

test("gate_guard falls back only when neither command nor path is given", async () => {
  const { get } = harness();
  const g = get("gate_guard");
  const r = await g.execute(deliver(g, {}), exec);
  assert.equal(r.verdict, "WARN");
  assert.ok(r.reasons.some((x) => x.includes("provide either")));
});
