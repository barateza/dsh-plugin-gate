# Release checklist (dsh-plugin-gate)

1. **Write** — plugin code: package.json (dsh.bundle + peerDeps), cordis.patch.yml, lib/{index,rules,scan,targz}.js.
2. **Verify** —
   - `node --check` on every lib/test file;
   - `node test/rules.test.mjs` and `node test/scan.test.mjs` (main-module mode; `node --test` is blocked in the DSH sandbox);
   - combination dump: `node <dsh>/lib/bin.js --profile web --patch ./cordis.patch.yml --dump-config` shows the `gate` row;
   - real npm smoke: `scanNpmPackage('dsh-plugin-focus')`.
3. **Publish npm** — `pwsh scripts/publish-npm.ps1` (reads token from $DSH_HOME/secrets/npm-token.txt).
4. **Topic** — add `dsh-plugin` (+ `deepseek-harness`, `cordis`, `security`) to the GitHub repo topics.
5. **awesome PR** — data/plugins/863683348__dsh-plugin-gate.yml + generate-readme.mjs; meet the 1-day / 10-commit bar; re-run CI after 24h with an empty commit if the age check fails.
