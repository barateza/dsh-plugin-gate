import { name, inject, Config, apply } from "../lib/index.js";
const tools = [];
const ctx = {
  tools: { register: (t) => tools.push(t) },
  systemPrompt: { section: (s) => { return () => {}; } },
  effect: (fn) => fn(),
  fs: {},
};
const config = Config();
apply(ctx, config);
console.log("name=" + name);
console.log("inject=" + JSON.stringify(inject));
console.log("tools=" + tools.map((t) => t.name).join(","));
for (const w of ["gate_scan", "gate_guard"]) if (!tools.some((t) => t.name === w)) throw new Error("missing " + w);
console.log("SMOKE OK");
