# Preparing a release

The project version lives in [VERSION](../VERSION). `make` embeds it in
`bin/coffin --version`. The current `0.1.0` is release preparation, not an
already published release.

## Local checks

```sh
make test
make differential
make sanitize
make fuzz-smoke
make fuzz
python3 tests/run_fuzz.py bin/fuzz/coffin-fuzz --runs 10000
make package
```

Independent comparisons require at least one installed oracle. Linux CI requires
GNU `readelf` and `llvm-readobj`; macOS CI requires `otool`. Locally LLVM tools
are found through `PATH`, `LLVM_BIN`, or standard Homebrew prefixes. Missing
optional tools are printed as skips; a required missing tool fails the check.

`make package` writes a host-specific archive and SHA-256 sidecar in `dist/`.
It includes the tested executable, README, license, changelog, and version file.
Archives are not reproducible-build claims: compiler, platform, and archive
metadata may differ. The binary is built for the current OS/CPU and uses that
platform's runtime libraries; test it on the oldest OS you intend to support.

Installation can be tested without administrator access:

```sh
make install DESTDIR=/tmp/coffin-stage PREFIX=/usr
/tmp/coffin-stage/usr/bin/coffin --version
make uninstall DESTDIR=/tmp/coffin-stage PREFIX=/usr
```

Use an empty staging directory of your choice. Uninstall removes only the
installed coffin executable and its documentation files; shared directories
remain. With no DESTDIR, the default prefix is `/usr/local`; choose a user-owned
prefix when administrator access is unavailable.

## Tag and publish checklist

1. Select the release version in `VERSION` and update `CHANGELOG.md` with the
   actual release date when ready. Review parser limits and supported behavior.
2. Commit the intended source, tests, documentation, and any deliberately rebuilt
   fixtures with their manifest. Do not include `bin/`, `obj/`, `dist/`, or fuzz
   corpora. Run the local checks above.
3. Push the release commit and require its Linux **and** macOS CI jobs to pass
   before creating a tag. A local macOS pass does not verify Linux behavior.
4. Create and push a tag exactly matching `v` plus `VERSION`, for example
   `v0.1.0`. Tag builds reject a version mismatch and run the full matrix again.
5. Wait for the `release-candidates` job. It depends on both matrix jobs and
   exposes `verified-release-candidates` only after all required checks pass.
   The ordinary CI jobs keep staging archives as `candidate-*` artifacts; those
   are not a release approval if another platform failed.
6. Download the verified archives and check their SHA-256 sidecars. Review the
   release notes, then create the GitHub release and attach the verified files.

The workflows prepare artifacts; they do not create tags, publish a GitHub
release, or configure branch/tag protection. Release maintainers perform those
steps explicitly. For server-enforced restrictions, configure repository rules
so only release maintainers can create version tags after reviewing CI.

## Longer fuzzing and failure follow-up

The separate `Extended fuzzing` workflow runs daily at 04:23 UTC or by manual
workflow dispatch. It gives libFuzzer 30 minutes and retains its evolving corpus
through an Actions cache. Corpus discoveries are saved even if a crash ends a
run. Logs, artifacts, and the corpus are uploaded for 14 days. GitHub schedules
can be delayed; this is a recurring test budget, not an exact-time guarantee.

To reproduce a failure locally:

```sh
make fuzz
bin/fuzz/coffin-fuzz path/to/crash-artifact
```

Reduce the input before turning it into a regression test:

```sh
bin/fuzz/coffin-fuzz -minimize_crash=1 -exact_artifact_path=/tmp/coffin-minimized path/to/crash-artifact
```

Confirm that the minimized bytes still fail, then add a focused fixture/assertion
in `tests/test_malformed.py` or a dedicated C unit test. Keep the expected behavior
explicit: malformed input should normally return an error, not crash or hang.
Raw generated corpora remain outside Git; small purposeful regression inputs
belong in the test source.
