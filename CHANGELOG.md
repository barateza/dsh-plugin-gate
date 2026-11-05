# Changelog

All notable changes to this fork. The fork starts from upstream `dsh-plugin-gate` 1.3.2
(2026-09-11); entries below are relative to that release.

## 1.3.3 — 2026-11-05

### Fixed

- **`gate_guard` could never return `BLOCK` or `PASS`.** The three parameters were declared
  nested under a single `input` object, while `execute` read `args.command` / `args.path` /
  `args.action`. Every call therefore hit the "provide either command or path" fallback, so the
  pre-destructive-command check was inert: `rm -rf /` and `rm -rf ./node_modules` produced the
  same answer. They are now declared as direct parameters, matching the sibling tools and the
  `execute` reads. (Upstream issue #5, PR #6.)
- **`gate_report` failed on every call without `write: true`.** The result advertised
  `path: writtenPath` even when nothing was written, and `undefined` anywhere in a tool result
  is rejected by the host's lossless-JSON validator (`value is not lossless JSON`). The key is
  now omitted unless a report file was written. (Upstream issue #4, PR #7.)

### Changed

- `package.json` declares `engines.dsh: ">=0.2.0-rc.2 <0.3.0"`. When `engines.dsh` is present
  the harness evaluates it instead of the `@deepseek-ai/dsh-*` peer ranges, so the plugin no
  longer needs an exact per-version exemption in `compatibility.json` to load on the tested
  0.2.x line.
- Package renamed to `@barateza/dsh-plugin-gate` (the `dsh-plugin-gate` npm name belongs to
  upstream); repository/homepage/bugs point at this fork.

### Added

- `test/gate-guard.test.mjs` and `test/gate-report.test.mjs`: contract tests covering the two
  regressions above, including a mirror of the host's lossless-JSON walker.
- `FORK.md`: what this fork is, the delta from upstream, the tested harness range and the
  maintenance policy.

### CI

- The `test` workflow now installs with `npm install` and no longer uses `cache: npm`. With no
  lockfile tracked, `actions/setup-node` failed with *"Dependencies lock file is not found"* and
  `npm ci` would have exited `EUSAGE` — the suite had never actually run. (Upstream PR #8.)
- Full suite: 68 tests, 8 files, passing.
