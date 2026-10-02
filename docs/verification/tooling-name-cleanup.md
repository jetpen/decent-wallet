# Issue-18 tooling-name cleanup inventory

This inventory classifies the 45 tracked paths that used the `issue18` name before
this cleanup. The rename is naming-only; it does not change wallet, Registry,
Android, or acceptance behavior.

## Maintained tooling — 11 paths renamed

Scripts:

- `scripts/run_wallet_registry_acceptance.py`
- `scripts/run_android_lan_host_acceptance.py`
- `scripts/run_remote_registry_acceptance.py`
- `scripts/remote_registry_fixture.py`

Tests:

- `tests/test_android_lan_host_harness.py`
- `tests/test_android_lan_host_runner.py`
- `tests/test_podman_registry_deployment.py`
- `tests/test_wallet_registry_acceptance_harness.py`
- `tests/test_remote_registry_acceptance.py`
- `tests/test_remote_registry_fixture.py`
- `tests/test_run_remote_registry_acceptance.py`

Imports, dynamic Python module names, test selectors, Gradle property, CLI examples,
fixture temporary-root prefix, cleanup marker, and process metadata use purpose-based
names to match these maintained paths. The unrelated Issue #18 history statements
remain as prose rather than executable identifiers.

## Archived verification evidence — 34 paths retained

All 34 artifacts below `docs/verification/issue18-android-storage/` remain at their
original paths as an immutable historical evidence bundle:

- `api26/`: 7 captured device configuration, command, result, and log/report files.
- `api37/`: 7 captured device configuration, command, result, and log/report files.
- `jvm/`: 10 captured JVM test reports.
- Bundle root: 10 manifests, summaries, logs, and review/static-scan records.

The directory name, captured commands, logs, and source-manifest hashes identify
the historical Issue #18 run and original source paths. Renaming those artifacts or
rewriting their contents would make their provenance less auditable. They are not
maintained tooling or executable interfaces.

## Count check

Before renaming, the tracked-path inventory contained 45 matches: 11 maintained
scripts/tests and 34 archived verification artifacts. This split accounts for the
complete tracked-path inventory; no other tracked `issue18`-named paths remain.
