import { test } from "node:test";
import assert from "node:assert/strict";
import { checkOsvDeps, exactVersion, exactVersionDeps, queryOsv } from "../lib/osv.js";

test("exactVersion accepts pinned versions and rejects ranges/specs", () => {
  assert.equal(exactVersion("1.2.3"), "1.2.3");
  assert.equal(exactVersion("1.2.3-alpha.1"), "1.2.3-alpha.1");
  assert.equal(exactVersion("1.2"), "1.2");
  assert.equal(exactVersion("^1.2.3"), null);
  assert.equal(exactVersion("~1.2.3"), null);
  assert.equal(exactVersion(">=1.0.0"), null);
  assert.equal(exactVersion("1.x"), null);
  assert.equal(exactVersion("latest"), null);
  assert.equal(exactVersion("git+https://github.com/x/y.git"), null);
  assert.equal(exactVersion("file:../x"), null);
  assert.equal(exactVersion("https://example.com/x.tgz"), null);
  assert.equal(exactVersion(undefined), null);
});

test("exactVersionDeps filters, caps and skips the official scope", () => {
  const deps = exactVersionDeps({
    "zod": "^4.4.3",
    "fast-deep-equal": "3.1.3",
    "left-pad": "1.3.0",
    "@deepseek-ai/cordis": "^4.0.1",
    "plain": "0.1.0",
    "a": "1.0.0",
    "b": "2.0.0",
    "c": "3.0.0",
    "d": "4.0.0",
    "e": "5.0.0",
    "f": "6.0.0",
  }, { max: 4 });
  assert.deepEqual(deps.map((d) => d.name), ["fast-deep-equal", "left-pad", "plain", "a"]);
  assert.ok(deps.every((d) => !d.name.startsWith("@deepseek-ai")));
});

test("queryOsv returns vulns for a hit and degrades on network failure", async () => {
  const hitFetch = async () => ({
    ok: true,
    json: async () => ({ vulns: [{ id: "GHSA-xxxx", summary: "RCE in demo", aliases: ["CVE-2026-0001"], modified: "2026-01-01T00:00:00Z" }] }),
  });
  const r1 = await queryOsv(hitFetch, "demo", "1.0.0");
  assert.equal(r1.ok, true);
  assert.equal(r1.vulns.length, 1);
  assert.equal(r1.vulns[0].id, "GHSA-xxxx");

  const failFetch = async () => { throw new Error("ECONNRESET"); };
  const r2 = await queryOsv(failFetch, "demo", "1.0.0");
  assert.equal(r2.ok, false);
  assert.match(r2.error, /ECONNRESET/);
});

test("checkOsvDeps aggregates hits and notes, tolerates partial failures", async () => {
  let calls = 0;
  const fake = async () => {
    calls += 1;
    if (calls === 1) return { ok: true, json: async () => ({ vulns: [{ id: "GHSA-1", summary: "bad" }] }) };
    throw new Error("timeout");
  };
  const { hits, notes, checked, vulnerable } = await checkOsvDeps(fake, [
    { name: "a", version: "1.0.0" },
    { name: "b", version: "2.0.0" },
  ]);
  assert.equal(checked, 1);
  assert.equal(vulnerable, 1);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].rule, "osv_vulnerability");
  assert.equal(hits[0].severity, "medium");
  assert.ok(notes.some((n) => n.kind === "osv"));
});

test("checkOsvDeps with no deps does nothing", async () => {
  const { hits, notes } = await checkOsvDeps(async () => { throw new Error("should not be called"); }, []);
  assert.equal(hits.length, 0);
  assert.equal(notes.length, 0);
});
