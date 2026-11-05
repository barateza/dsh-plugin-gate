# Changelog

All notable changes to this fork. The fork starts from upstream `dsh-plugin-gate` 1.3.2
(2026-09-11); entries below are relative to that release.

## 1.3.8 — 2026-11-05

### CI

- `actions/checkout` and `actions/setup-node` bumped to **v6**. The v4 actions target Node 20, which
  GitHub now forces onto Node 24 and annotates on every run as deprecated, and
  `package-manager-cache` — used by the publish workflow to keep automatic caching off — is not a
  valid input on v4 ("Unexpected input(s) …"). The `test` workflow now completes with no
  annotations; the remaining `ubuntu-latest` → Ubuntu 26 notice is a runner-image migration note,
  not an error.
- Documentation-only version: this tag exists to exercise the updated `publish.yml` through trusted
  publishing (OIDC staging) before the next real release.

## 1.3.7 — 2026-11-05

_Tagged once as 1.3.6; that tag never published — CI failed on the peer-metadata regression below
before anything was staged, so no artifact exists for it. The fixes here are unchanged by that._

### Security

- **`dist.tarball` is no longer fetched unvalidated.** The registry returns the tarball URL as
  package metadata, and `scanNpmPackage` previously fetched whatever it named. A malicious
  package — or a compromised or misconfigured mirror — could therefore point a scan at an
  internal host (`169.254.169.254`, `127.0.0.1`, a private network) and make the gate issue the
  request on its behalf. A low-grade SSRF surface, and an odd one for a security tool to carry.

  `assertSafeTarballUrl` now runs before any request: **https only**, the host must be in
  `allowedTarballHosts` (default `["registry.npmjs.org"]`), and loopback, link-local,
  private-range, CGNAT, multicast and unique-local IPv6 addresses are refused outright. A
  redirect whose final URL lands on a private address is refused too. The rejection names the
  package, version and reason instead of a generic download error.

  `allowedTarballHosts` is a scan option, not plugin config, so a mirror can be permitted
  deliberately. Private-registry scanning still does not work — the metadata lookup is pinned to
  `registry.npmjs.org` — and is tracked separately rather than silently half-enabled.

### Fixed

- **Reverted the 1.3.5 peer-metadata change; it made the package uninstallable for its own
  toolchain.** 1.3.5 marked the five DSH host packages `peerDependenciesMeta.optional` to silence
  pnpm's missing-peer warning. With optional peers, npm stops installing them, and `npm test`
  then died at `lib/index.js` importing `@deepseek-ai/schemastery` (`ERR_MODULE_NOT_FOUND`). CI
  caught this on the 1.3.6 tag — both the `test` and `publish` jobs failed before staging — which
  is why 1.3.6 was never released.

  The peer ranges are back to upstream's, and the two host packages the plugin entry actually
  imports (`@deepseek-ai/schemastery`, `@deepseek-ai/dsh-tools`) are now explicit
  `devDependencies` so a clean checkout can run the suite.

  The widened range from 1.3.5 was also wrong on its own terms: npm's semver does not match the
  `0.2.2-rc.1` prerelease against `>=0.1.0-rc.6 <0.3.0` (prereleases are only admitted for the
  same `major.minor.patch` as a comparator), so it resolved the old `0.1.0-rc.8` line regardless.
  The range bought nothing and created a resolution split. DeepSeek Harness ignores peer ranges
  when `engines.dsh` is declared, which it is — so `engines.dsh` remains the compatibility
  contract, and the missing-peer warning stays ecosystem-wide noise rather than something this
  package should trade installability for.

## 1.3.5 — 2026-11-05

### Fixed

- **A self-scan no longer BLOCKs the gate itself.** `gate_scan` of this package returned
  **BLOCK** because `lib/rules.js` *is* the signature catalogue and the tool descriptions and
  docs quote the same patterns; the verdict told every agent following the gate's own guidance
  to refuse the gate. A scan whose target package name is the gate's own
  (`dsh-plugin-gate` / `@barateza/dsh-plugin-gate`) now caps the verdict at **WARN**, sets
  `selfScan: true`, and keeps every finding visible with an explicit note. The cap is keyed on
  the package name, which only the gate can publish: the same content under any other name
  still returns **BLOCK**. Local-directory and tarball scans now report `package.name`, so the
  cap applies to `gate_scan` targets of every kind, not just npm specs.

### Changed

- Peer metadata widened from `^0.1.0-rc.6` to `>=0.1.0-rc.6 <0.3.0` for
  `@deepseek-ai/dsh-fs`, `@deepseek-ai/dsh-system-prompt` and `@deepseek-ai/dsh-tools`. The
  old ranges were 0.1.x-only and excluded 0.2.x, including the 0.2.2 line.
- All five DSH host packages are now `peerDependenciesMeta.optional`. DeepSeek Harness
  resolves them at load time from its own installation rather than installing them into the
  profile, so declaring them as required peers only produced missing-peer warnings on install.
  `pnpm install` of this package no longer reports peer issues.

## 1.3.4 — 2026-11-05

### Documentation

- README / README.zh: explain why `gate_scan` on this package itself returns **BLOCK** —
  `lib/rules.js` *is* the signature catalogue, so the patterns it hunts for appear in it as
  regular expressions, and the scanner cannot tell a definition from a use. The note also
  states what the package does not do (it never executes scanned code, never spawns a shell;
  its only outbound request is the optional OSV lookup at `api.osv.dev`).

### Release engineering

- First release submitted by CI through npm **trusted publishing** (OIDC): no npm token exists
  in this repository or anywhere else. The trusted publisher is scoped to **staged publishing
  only**, so CI stages the version and a maintainer approves it on npmjs.com with a security
  key — proof-of-presence stays with a human. 1.3.3 had been bootstrapped the same way
  (`npm stage publish` + manual approval), because a trusted publisher cannot be attached to a
  package that does not exist yet.

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
