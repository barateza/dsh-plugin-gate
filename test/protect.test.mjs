import test from "node:test";
import assert from "node:assert/strict";
import { evaluateCommand, evaluatePath } from "../lib/protect.js";

test("BLOCK: rm -rf / (root)", () => {
  const r = evaluateCommand("rm -rf /");
  assert.equal(r.verdict, "BLOCK");
});

test("BLOCK: rm -rf C:\ drive root", () => {
  const r = evaluateCommand("rm -rf C:\\");
  assert.equal(r.verdict, "BLOCK");
});

test("BLOCK: rmdir /s /q", () => {
  assert.equal(evaluateCommand("rmdir /s /q D:\\old").verdict, "BLOCK");
});

test("BLOCK: format drive / dd to device / mkfs", () => {
  assert.equal(evaluateCommand("format E:").verdict, "BLOCK");
  assert.equal(evaluateCommand("dd if=/dev/zero of=/dev/sda").verdict, "BLOCK");
  assert.equal(evaluateCommand("mkfs.ext4 /dev/sdb1").verdict, "BLOCK");
});

test("WARN: recursive rm inside workspace", () => {
  const r = evaluateCommand("rm -rf ./node_modules");
  assert.equal(r.verdict, "WARN");
  assert.ok(r.reasons.some((x) => x.includes("recursive")));
});

test("WARN: Remove-Item -Recurse", () => {
  assert.equal(evaluateCommand("Remove-Item -Recurse ./build").verdict, "WARN");
});

test("PASS: harmless commands", () => {
  assert.equal(evaluateCommand("npm run build").verdict, "PASS");
  assert.equal(evaluateCommand("git status").verdict, "PASS");
  assert.equal(evaluateCommand("").verdict, "PASS");
});

test("evaluatePath: workspace root is BLOCK, inside is WARN, outside is WARN", () => {
  const ws = "C:/work/proj";
  assert.equal(evaluatePath("C:/work/proj", ws).verdict, "BLOCK");
  assert.equal(evaluatePath("C:/work/proj/src/tmp", ws).verdict, "WARN");
  assert.equal(evaluatePath("C:/other/place", ws).verdict, "WARN");
  assert.equal(evaluatePath("/", ws).verdict, "BLOCK");
});

test("evaluatePath: critical files flagged", () => {
  const ws = "C:/work/proj";
  const r = evaluatePath("C:/work/proj/.dsh-memory-setup/memory.json", ws);
  assert.equal(r.verdict, "WARN");
  assert.ok(r.reasons.some((x) => x.includes("critical")));
});
