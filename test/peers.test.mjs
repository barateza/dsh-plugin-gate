import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// Packaging contract, not behaviour: the DSH host peers must describe the same
// release window as `engines.dsh`.
//
// Two evaluators read this manifest, and they disagree about what to do with
// peers:
//
//  1. The host loader (@deepseek-ai/dsh-app-boot, `evaluatePluginCompatibility`)
//     lets `engines.dsh` decide alone — when it is present, peer ranges are
//     never evaluated.
//  2. The plugin market (dshmarket, `deriveHostCompatibility`) folds every
//     `@deepseek-ai/dsh*` peer into the same verdict *conjunctively* with
//     `engines.dsh` and renders the intersection it read
//     (`>=0.2.0-rc.2 <0.3.0 ∩ ^0.1.0-rc.6`).
//
// A peer left on upstream's 0.1 line is therefore invisible to the host and
// fatal to the market: 1.3.7/1.3.8 kept `^0.1.0-rc.6` on `dsh-fs`,
// `dsh-system-prompt` and `dsh-tools`, so the market refused to update to
// 1.3.8 on a 0.2.2-rc.1 host that the host loader itself would have accepted.
//
// DSH publishes the host packages on its own lockstep line — the 0.2.2-rc.1
// installation ships `dsh-fs`, `dsh-system-prompt` and `dsh-tools` at
// 0.2.2-rc.1 — so a DSH peer has no honest range of its own. Mirroring
// `engines.dsh` keeps the two evaluators in agreement; widening or narrowing
// the peer window is a decision that must move `engines.dsh` with it.
const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

const dshPeers = () =>
  Object.entries(manifest.peerDependencies ?? {}).filter(([name]) =>
    /^@deepseek-ai\/dsh(?:-|$)/.test(name),
  );

test("engines.dsh declares the supported DSH window", () => {
  assert.equal(typeof manifest.engines?.dsh, "string");
  assert.notEqual(manifest.engines.dsh.trim(), "");
});

test("every DSH host peer mirrors engines.dsh", () => {
  const engine = manifest.engines.dsh;
  const peers = dshPeers();
  assert.ok(peers.length > 0, "expected the DSH host packages as peers");
  for (const [name, range] of peers) {
    assert.equal(
      range,
      engine,
      `${name} declares ${range} while engines.dsh declares ${engine}; ` +
        "the market intersects the two and refuses installs the host accepts",
    );
  }
});

test("test dependencies pin the declared DSH line", () => {
  // The suite imports @deepseek-ai/dsh-tools (defineTool) at module load, so the
  // test tree is what the tests exercise — it has to be the runtime tree. A peer
  // *range* does not get there: npm resolves it to the highest version with a
  // comparator for that exact tuple, so `>=0.2.0-rc.2` installs 0.2.0-rc.2, not
  // the 0.2.2-rc.1 the host runs, and that 0.2.0 prerelease pulls a cordis
  // `~4.0.4` peer that conflicts with the 4.1.0 host tree (ERESOLVE). Pinning
  // the three host packages keeps the suite on the lockstep line the host ships.
  const line = (version) => version.split("-")[0].split(".").slice(0, 2).join(".");
  const [floor] = manifest.engines.dsh.match(/\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?/);
  const deps = Object.entries(manifest.devDependencies ?? {}).filter(([name]) =>
    /^@deepseek-ai\/dsh(?:-|$)/.test(name),
  );
  assert.ok(deps.length > 0, "expected the DSH host packages the suite resolves");
  for (const [name, version] of deps) {
    assert.match(
      version,
      /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/,
      `${name} must be pinned to an exact version, not a range`,
    );
    assert.equal(
      line(version),
      line(floor),
      `${name}@${version} is not on the ${line(floor)} line engines.dsh declares`,
    );
  }
});

test("non-DSH peers are left alone", () => {
  // cordis and schemastery are host packages but not on DSH's lockstep 0.x
  // line (4.x/3.x), so they must not be forced onto the DSH window.
  const cordis = manifest.peerDependencies?.["@deepseek-ai/cordis"];
  const schemastery = manifest.peerDependencies?.["@deepseek-ai/schemastery"];
  assert.equal(typeof cordis, "string");
  assert.equal(typeof schemastery, "string");
  assert.notEqual(cordis, manifest.engines.dsh);
  assert.notEqual(schemastery, manifest.engines.dsh);
});
