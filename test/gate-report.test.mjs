import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { apply, Config } from "../lib/index.js";

// Regression test for #4: gate_report returned `path: writtenPath`
// unconditionally, so every call without `write: true` carried an own
// enumerable `path` whose value was `undefined`. The host validates each tool
// result with a lossless-JSON walker that rejects `undefined` anywhere in the
// tree — unlike JSON.stringify, which drops it — so the tool failed with
// "value is not lossless JSON" on every target.
//
// `firstUndefined` mirrors that walker rather than asserting on one field, so a
// future `undefined` anywhere in the result fails here too.

function firstUndefined(value, at = "<result>") {
  if (value === undefined) return at;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const hit = firstUndefined(value[i], `${at}[${i}]`);
      if (hit) return hit;
    }
    return null;
  }
  if (value && typeof value === "object") {
    for (const k of Object.keys(value)) {
      const hit = firstUndefined(value[k], `${at}.${k}`);
      if (hit) return hit;
    }
    return null;
  }
  return null;
}

function harness() {
  const tools = [];
  const ctx = {
    tools: { register: (t) => tools.push(t) },
    systemPrompt: { section: () => () => {} },
    effect: (fn) => fn(),
    fs: {
      resolve: async (p) => p,
      contains: () => true,
      stat: async () => undefined, // no baseline on disk -> skip the diff branch
      processPath: (p) => p,
      readText: async () => "",
      writeText: async () => {},
    },
  };
  apply(ctx, Config());
  return {
    get(name) {
      const t = tools.find((x) => x.name === name);
      assert.ok(t, `tool ${name} is not registered`);
      return t;
    },
  };
}

function tinyTarget() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gate-report-"));
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "tiny", version: "1.0.0" }));
  fs.writeFileSync(path.join(dir, "index.js"), "module.exports = {};\n");
  return dir;
}

const exec = { agent: { session: { header: { cwd: os.tmpdir() } } } };

test("gate_report omits `path` when nothing was written (#4)", async () => {
  const { get } = harness();
  const r = await get("gate_report").execute({ target: tinyTarget() }, exec);

  assert.ok(!("path" in r), "`path` must be omitted, not present with value undefined");
  assert.equal(firstUndefined(r), null, `result carries undefined at ${firstUndefined(r)}`);
  assert.equal(typeof r.text, "string");
});

test("gate_report keeps `path` when write:true", async () => {
  const { get } = harness();
  const out = path.join(os.tmpdir(), "gate-report-written.md");
  const r = await get("gate_report").execute({ target: tinyTarget(), write: true, path: out }, exec);

  assert.equal(r.path, out);
  assert.equal(firstUndefined(r), null, `result carries undefined at ${firstUndefined(r)}`);
});
