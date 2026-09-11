import { test } from "node:test";
import assert from "node:assert/strict";
import { groupHits, renderJsonReport, renderMarkdownReport } from "../lib/report.js";

const sample = {
  verdict: "BLOCK",
  score: 40,
  filesScanned: 12,
  hosts: ["evil.example.com", "registry.npmjs.org"],
  summary: { high: 1, medium: 1, low: 1, categories: { scripts: 1, network: 1, obfuscation: 1 } },
  hits: [
    { rule: "net_fetch", category: "network", severity: "medium", file: "lib/net.js", line: 5, count: 1, evidence: "fetch(\"https://evil.example.com\")" },
    { rule: "eval_call", category: "obfuscation", severity: "high", file: "lib/x.js", line: 2, count: 1, evidence: "eval(payload)" },
    { rule: "hex_escapes", category: "obfuscation", severity: "low", file: "lib/y.js", line: 9, count: 2, evidence: "\\x41\\x42" },
  ],
  recommendations: ["BLOCK: high-severity patterns found."],
};

test("groupHits orders by severity then category", () => {
  const groups = groupHits(sample.hits);
  assert.equal(groups.length, 3);
  assert.equal(groups[0].severity, "high");
  assert.equal(groups[0].category, "obfuscation");
  assert.equal(groups[1].severity, "medium");
  assert.equal(groups[2].severity, "low");
  assert.equal(groups[0].hits[0].rule, "eval_call");
});

test("groupHits tolerates empty and malformed input", () => {
  assert.deepEqual(groupHits([]), []);
  assert.deepEqual(groupHits(undefined), []);
  assert.equal(groupHits([{ severity: "high" }]).length, 0, "rule-less hits dropped");
});

test("renderMarkdownReport includes header, groups and recommendations", () => {
  const md = renderMarkdownReport({ target: "npm:dsh-plugin-x", result: sample, date: "2026-08-22T00:00:00Z" });
  assert.ok(md.startsWith("# Gate scan report: npm:dsh-plugin-x"));
  assert.ok(md.includes("- Verdict: **BLOCK** (risk score 40)"));
  assert.ok(md.includes("- Findings: high 1 / medium 1 / low 1"));
  assert.ok(md.includes("## HIGH · obfuscation (1)"));
  assert.ok(md.includes("| eval_call | lib/x.js | 2 | 1 |"));
  assert.ok(md.includes("## Recommendations"));
  assert.ok(md.includes("BLOCK: high-severity patterns found."));
});

test("renderMarkdownReport escapes pipes and reports a clean scan", () => {
  const md = renderMarkdownReport({
    target: "t",
    result: { verdict: "PASS", hits: [{ rule: "r", category: "c", severity: "low", file: "a.js", line: 1, count: 1, evidence: "a | b" }], recommendations: [] },
  });
  assert.ok(md.includes("a \\| b"), "pipe escaped in evidence");
  const clean = renderMarkdownReport({ target: "t", result: { verdict: "PASS", hits: [], summary: { high: 0, medium: 0, low: 0 } } });
  assert.ok(clean.includes("No findings."));
});

test("renderMarkdownReport mentions the baseline diff when present", () => {
  const md = renderMarkdownReport({
    target: "t",
    result: sample,
    diff: { hasBaseline: true, clean: false, counts: { added: 2, resolved: 0, changed: 0, unchanged: 1 }, baselineUpdatedAt: "2026-08-01T00:00:00Z" },
  });
  assert.ok(md.includes("Baseline diff: new 2 / changed 0 vs 2026-08-01T00:00:00Z"));
});

test("renderJsonReport is stable and parseable", () => {
  const json = renderJsonReport({ target: "npm:x", result: sample, date: "2026-08-22T00:00:00Z", diff: { hasBaseline: true, clean: false, counts: { added: 1, resolved: 0, changed: 0, unchanged: 2 }, verdictChange: { from: "WARN", to: "BLOCK" } } });
  const doc = JSON.parse(json);
  assert.equal(doc.generator, "dsh-plugin-gate");
  assert.equal(doc.target, "npm:x");
  assert.equal(doc.verdict, "BLOCK");
  assert.equal(doc.summary.high, 1);
  assert.equal(doc.findings.length, 3);
  assert.equal(doc.findings[0].severity, "high");
  assert.equal(doc.findings[0].hits[0].rule, "eval_call");
  assert.deepEqual(doc.baselineDiff.counts, { added: 1, resolved: 0, changed: 0, unchanged: 2 });
  assert.equal(doc.baselineDiff.verdictChange.to, "BLOCK");
});

test("renderJsonReport omits the diff when none is supplied", () => {
  const doc = JSON.parse(renderJsonReport({ target: "t", result: { verdict: "PASS", hits: [] } }));
  assert.equal(doc.baselineDiff, null);
  assert.deepEqual(doc.findings, []);
});
