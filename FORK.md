# Fork notice

This package is an **unofficial maintained fork** of
[`863683348/dsh-plugin-gate`](https://github.com/863683348/dsh-plugin-gate),
published as [`@barateza/dsh-plugin-gate`](https://www.npmjs.com/package/@barateza/dsh-plugin-gate)
under the MIT license (original copyright © 2026 863683348, retained in [LICENSE](./LICENSE)).

## Why fork

Upstream stopped responding in September 2026. As of 2026-11-04:

- last commit and npm release: 2026-09-11 (`1.3.2`);
- issues unanswered since 2026-08-21, including reports from five different authors;
- four open pull requests with no review or comment (three from this fork's maintainer,
  opened 2026-09-25);
- the `test` workflow had never run: `actions/setup-node` with `cache: npm` fails when no
  lockfile is tracked, so every push failed before `node --test`.

Two of those defects made the safety features inert:

| Defect | Effect in 1.3.2 |
| --- | --- |
| `gate_guard` declared `command` / `path` / `action` nested under a single `input` object while `execute` read `args.command` / `args.path` | the tool could only ever return `WARN: provide either command or path` — it never returned `BLOCK` or `PASS`, so the pre-destructive-command check did nothing |
| `gate_report` returned `path: undefined` when `write` was not `true` | every call without `write: true` failed with `value is not lossless JSON` |

`lib/protect.js` (the rules engine) was correct throughout; only the tool wiring was broken.

## Delta from upstream 1.3.2

- `fix(gate_guard)`: declare `command` / `path` / `action` as direct parameters
  (upstream issue #5, PR #6).
- `fix(gate_report)`: omit `path` instead of returning `undefined`
  (upstream issue #4, PR #7).
- `ci(test)`: replace `npm ci` with `npm install` and drop `cache: npm`, which had never run
  the suite (upstream PR #8).
- `engines.dsh: ">=0.2.0-rc.2 <0.3.0"`: when `engines.dsh` is present the harness checks that
  range **instead of** peer ranges. Upstream pinned `@deepseek-ai/dsh-*` peers at
  `^0.1.0-rc.6`, so every 0.2.x install needed a manual, per-version exemption
  (`compatibility.json`) granted with `dsh plugin allow-version`. This fork installs on the
  tested 0.2.x line without an exemption.
- Two regression tests (`test/gate-guard.test.mjs`, `test/gate-report.test.mjs`) that assert the
  parameter/result contract, not just tool presence.
- `chore`: drop the stray `.npm-cache-pub3/` and `.npm-cache-pub4/` npm debug-log directories
  that upstream tracked, and stop tracking `package-lock.json` (CI keeps `npm install`, per
  PR #8, since neither lockfile was previously committed).

Everything else — rules, scanner, report renderer, roadmap — is upstream's, unchanged.

## Maintenance policy

This is a low-volume fork, not a re-launch of the project:

- **Harness compatibility is re-verified on each DSH release.** The supported window is
  declared in `engines.dsh` and raised only after the suite passes on that runtime.
- **If the window is not re-verified, the package is deprecated rather than left silently
  stale.** A security scanner that quietly misses detections is worse than no scanner.
- **Releases are cut by pushing a `v*` tag.** `.github/workflows/publish.yml` publishes through
  npm **trusted publishing** (OIDC): no npm token exists in this repository, in GitHub secrets,
  or on any machine, and the workflow fails closed if the OIDC exchange is not authorized. The
  workflow also attaches a provenance statement. Node 24 / npm >= 11.5.1 are required.
- **The first release was bootstrapped through staged publishing**, not a bypass-2FA token:
  `npm stage publish` (which needs no 2FA) plus an approval on npmjs.com with a security key.
  A trusted publisher cannot be attached to a package that does not exist yet, so exactly one
  release had to be approved by hand.
- **Security tool caveat, unchanged from upstream** ([SECURITY.md](./SECURITY.md)): this is a
  heuristic scanner. It can miss novel malware and can over-flag innocent code. A `PASS` is
  not a guarantee.
- Issues and patches: <https://github.com/barateza/dsh-plugin-gate/issues>.
- If upstream resumes and merges the fixes, this fork will be deprecated in favour of
  `dsh-plugin-gate`.
