import { test } from "node:test";
import assert from "node:assert/strict";
import {
  BASELINE_VERSION,
  buildBaseline,
  diffBaseline,
  fingerprintResult,
  hitFingerprint,
  renderDiff,
} from "../lib/baseline.js";

const hit = (rule, severity, file, line = 1, count = 1) => ({ rule, severity, file, line, count });

test("hitFingerprint is stable and ignores line numbers", () => {
  assert.equal(hitFingerprint(hit("eval_call", "high", "lib/a.js", 10)), "eval_call|high|lib/a.js");
  assert.equal(hitFingerprint(hit("eval_call", "high", "lib/a.js", 999)), hitFingerprint(hit("eval_call", "high", "lib/a.js", 1)));
  assert.equal(hitFingerprint({}), "?|?|?");
});

test("fingerprintResult counts hits per fingerprint", () => {
  const counts = fingerprintResult({ hits: [hit("r1", "high", "a.js"), hit("r1", "high", "a.js"), hit("r2", "low", "b.js")] });
  assert.equal(counts.get("r1|high|a.js"), 2);
  assert.equal(counts.get("r2|low|b.js"), 1);
  assert.equal(counts.size, 2);
});

test("buildBaseline records verdict, summary and fingerprints", () => {
  const doc = buildBaseline({
    target: "npm:dsh-plugin-x",
    date: "2026-08-22T00:00:00Z",
    result: { verdict: "WARN", score: 12, summary: { high: 0, medium: 1, low: 0, categories: {} }, hits: [hit("net_fetch", "medium", "lib/net.js", 5, 3)] },
  });
  assert.equal(doc.version, BASELINE_VERSION);
  assert.equal(doc.target, "npm:dsh-plugin-x");
  assert.equal(doc.verdict, "WARN");
  assert.equal(doc.updatedAt, "2026-08-22T00:00:00Z");
  assert.deepEqual(doc.hits, [{ fp: "net_fetch|medium|lib/net.js", count: 3 }]);
});

test("diffBaseline without a stored baseline reports hasBaseline=false", () => {
  const d = diffBaseline({ baseline: null, result: { verdict: "PASS", hits: [] }, target: "t" });
  assert.equal(d.hasBaseline, false);
  assert.equal(d.counts.unchanged, 0);
  assert.equal(d.clean, true);
  const withFindings = diffBaseline({ baseline: null, result: { verdict: "WARN", hits: [hit("r", "medium", "f.js")] }, target: "t" });
  assert.equal(withFindings.clean, false, "new findings without a baseline are not clean");
  assert.equal(withFindings.counts.added, 1);
});

test("diffBaseline classifies added, resolved, changed and unchanged", () => {
  const baseline = buildBaseline({ target: "t", result: { verdict: "WARN", hits: [hit("keep", "medium", "a.js"), hit("gone", "low", "b.js"), hit("grew", "low", "c.js", 1, 1)] } });
  const result = { verdict: "WARN", hits: [hit("keep", "medium", "a.js"), hit("grew", "low", "c.js", 9, 4), hit("new", "high", "d.js")] };
  const d = diffBaseline({ baseline, result, target: "t" });
  assert.equal(d.hasBaseline, true);
  assert.deepEqual(d.added.map((x) => x.fp), ["new|high|d.js"]);
  assert.deepEqual(d.resolved.map((x) => x.fp), ["gone|low|b.js"]);
  assert.deepEqual(d.changed.map((x) => x.fp), ["grew|low|c.js"]);
  assert.equal(d.changed[0].was, 1);
  assert.equal(d.changed[0].count, 4);
  assert.deepEqual(d.unchanged.map((x) => x.fp), ["keep|medium|a.js"]);
  assert.equal(d.clean, false, "added and changed findings are not clean");
});

test("diffBaseline marks a clean fix and verdict transitions", () => {
  const baseline = buildBaseline({ target: "t", result: { verdict: "BLOCK", hits: [hit("bad", "high", "a.js")] } });
  const d = diffBaseline({ baseline, result: { verdict: "PASS", hits: [] }, target: "t" });
  assert.equal(d.clean, true);
  assert.equal(d.counts.resolved, 1);
  assert.deepEqual(d.verdictChange, { from: "BLOCK", to: "PASS" });
});

test("renderDiff renders both the no-baseline and diff cases", () => {
  const fresh = renderDiff({ diff: diffBaseline({ baseline: null, result: { verdict: "PASS", hits: [] }, target: "npm:x" }), target: "npm:x" });
  assert.ok(fresh.startsWith("# Baseline diff: npm:x"));
  assert.ok(fresh.includes("No baseline stored"));

  const baseline = buildBaseline({ target: "npm:x", result: { verdict: "WARN", hits: [hit("old", "medium", "a.js")] } });
  const d = diffBaseline({ baseline, result: { verdict: "BLOCK", hits: [hit("new", "high", "b.js")] }, target: "npm:x" });
  const text = renderDiff({ diff: d, target: "npm:x" });
  assert.ok(text.includes("Verdict: WARN -> BLOCK"));
  assert.ok(text.includes("## Added"));
  assert.ok(text.includes("| new|high|b.js | 1 |"));
  assert.ok(text.includes("## Resolved"));
  assert.ok(text.includes("New or worsened findings detected"));
});
