# Distribution packages

All package builds use current source bytes in a temporary tree. Ordinary `make`
and `make test` do not install packages. Installation tests are explicit and
intended for disposable CI machines; they refuse to replace existing Coffin
installations.

## Debian / Ubuntu

On Linux with Debian packaging tools:

```sh
sudo apt-get install build-essential debhelper dpkg-dev python3
make deb
```

This runs the functional tests and builds `dist/coffin_VERSION-1_ARCH.deb` plus a
SHA-256 sidecar. Pre-release versions use Debian's `~` ordering. Build with the
native architecture's toolchain; cross-compilation is not configured. CI tests
`amd64` on Debian 12 (bookworm), including automatically determined runtime
library dependencies. Compatibility with older distributions is not promised.

Install a downloaded package and later remove it:

```sh
sudo apt install ./coffin_0.1.0-1_amd64.deb
coffin --version
sudo apt remove coffin
```

CI runs `tests/test_deb.py` as root in its disposable container: install, inspect
ELF/PE/Mach-O files, reject a truncated file, remove, reinstall, and purge. It
checks that every installed package-owned file disappears. The package contains
no maintainer scripts and installs no services or configuration files.

Metadata and debhelper rules live in `packaging/debian/`. The builder renders the
Debian changelog from VERSION and SOURCE_DATE_EPOCH (or the Git commit timestamp preserved in the source snapshot).
It builds binary packages without signing or publishing them.

## Homebrew

Generate the source archive and formula:

```sh
make homebrew
```

Outputs are `dist/coffin-VERSION-source.tar.gz`, its SHA-256 sidecar, and
`dist/coffin.rb`. The formula builds from source, using the real archive checksum.
Its release URL points to that exact archive as an asset on the matching GitHub
release. Do not substitute GitHub's automatically generated tag archive: its
bytes and checksum differ. No placeholder URL/checksum is published.

The formula installs three small known-source parser fixtures under its share
directory. `brew test` checks version, reports and hashes across all three
formats, and malformed-file rejection; it never executes the fixture binaries.

On macOS, test from the local source archive without publishing:

```sh
python3 tests/test_homebrew.py dist/coffin-0.1.0-source.tar.gz
```

This creates a temporary local tap, builds and tests Coffin, reinstalls and tests
it again, uninstalls it, checks removal, and deletes the tap. It uses a local
file URL only in that disposable tap. The generated release formula stays
unchanged. Normal builds and tests can run without Homebrew.

After reviewing the tagged CI artifacts, upload the source archive and its
checksum to the GitHub release. Copy the matching generated `coffin.rb` to
`Formula/coffin.rb` in a separately created `jerryrw/homebrew-coffin` repository.
Users can then install and remove it with:

```sh
brew install jerryrw/coffin/coffin
brew test jerryrw/coffin/coffin
brew uninstall coffin
```

The tap repository is not created by these scripts. Bottles, tap publishing,
APT repositories, signing, and ARM Debian CI are future release work.

## CI artifacts and release gating

The package jobs run after the Linux/macOS verification matrix passes. Every
successful push/PR produces `candidate-debian` and `candidate-homebrew` workflow
artifacts. A version tag exposes `verified-release-candidates` only after both
package jobs and the parser matrix pass. Artifacts are candidates for review;
CI neither creates a tag nor publishes a release or a tap.

The source export normalizes archive metadata for stable source checksums. It
includes an explicit source-file list so extracted releases can rebuild and run
packaging tests without Git. This does not claim reproducible compiled binaries.
