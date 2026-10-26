# Distribution packages

All package builds use current source bytes in a temporary tree. Ordinary `make`
and `make test` do not install packages. Installation tests are explicit and
intended for disposable CI machines; they refuse to replace existing Coffin
installations.

## Install a release

1. Run `dpkg --print-architecture`. The published and CI-tested package is
   `amd64`; an ARM CPU being supported by the parser does not mean the amd64
   application package can run on that ARM machine.
2. Open [GitHub Releases](https://github.com/jerryrw/coffin/releases/latest).
   Download the `.deb` and its matching `.deb.sha256` asset. GitHub's automatic
   **Source code** downloads are not installable Debian packages.
3. Keep both files in the same directory and verify the download before installing:

   ```sh
   sha256sum -c coffin_0.1.1-1_amd64.deb.sha256
   sudo apt install ./coffin_0.1.1-1_amd64.deb
   /usr/bin/coffin --version
   /usr/bin/coffin --summary /usr/bin/ls
   ```

   Use the matching filenames for other versions. The checksum checks consistency
   with the published asset; it is not a package signature. `apt` checks runtime
   dependencies and resolves them from your configured distribution repositories.
   The `./` distinguishes a local package file from an APT repository package name.

The package is built and tested on Debian 12 (bookworm) amd64. Other Debian/Ubuntu
versions need compatible runtime libraries; older distributions and ARM packages
are not currently verified. If APT reports unmet dependencies, use a compatible
distribution or build natively from source; do not force installation past them.

### Upgrade and remove

Download a newer `.deb` and its matching checksum, verify it, then install it
with the same `sudo apt install ./filename.deb` command. Installed packages do
not automatically update from GitHub; an APT repository is not configured.

```sh
sudo apt remove coffin
# Or remove the package and any package configuration records:
sudo apt purge coffin
```

Coffin installs no services or configuration files. Removal leaves your input
binaries, saved reports, and extracted resources in place. Inspect package-owned
paths before removal with `dpkg -L coffin`.

### If the command reports the wrong version

Run `command -v coffin` and `/usr/bin/coffin --version`. A previous source install
in `/usr/local/bin` or a user directory can appear earlier in PATH than the Debian
binary. The Debian package owns `/usr/bin/coffin`; it does not remove another
installation. Use the old installation's own uninstall method if you want to
remove it, or invoke `/usr/bin/coffin` explicitly. `dpkg -s coffin` shows the
installed Debian package version.

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
sudo apt install ./coffin_0.1.1-1_amd64.deb
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

`make homebrew` prepares a source archive, its SHA-256 sidecar, and `dist/coffin.rb`.
The formula uses the archive's real checksum and the matching versioned GitHub
Release asset URL. It builds from source and installs three known-source parser
fixtures for `brew test`; those fixture binaries are inspected, never executed.

On macOS with Homebrew installed, test locally without publishing a tap:

```sh
make homebrew
python3 tests/test_homebrew.py dist/coffin-0.1.1-source.tar.gz
```

Use the matching filename if VERSION changes. The test creates a temporary local
tap using a file URL, installs and tests Coffin, reinstalls and tests it again,
then uninstalls it and removes the tap. It refuses to replace an existing Coffin
installation. The release formula stays unchanged.

In CI, the Homebrew job downloads and checks the source archive from the Debian
job, generates the formula from those exact bytes, and runs the same lifecycle
test. This ensures its SHA-256 matches the archive in the release assets.

To publish Homebrew distribution, first upload the verified source archive and
its checksum to the matching GitHub Release. Copy the generated `coffin.rb` into
`Formula/coffin.rb` in your `jerryrw/homebrew-coffin` tap repository. Only after
that tap exists and has been tested, users can run:

```sh
brew install jerryrw/coffin/coffin
brew test jerryrw/coffin/coffin
brew uninstall coffin
```

The workflows do not create or publish the tap automatically. GitHub's automatic
source-code archive is different from the generated release archive; use the
exact source asset named by the formula. Bottles are not currently built.

## CI artifacts and release gating

The Debian job runs after the Linux/macOS parser matrix passes. Homebrew runs
after Debian and reuses its source archive. Successful jobs produce
`candidate-debian` (the `.deb`, source archive, and their checksums) and
`candidate-homebrew` (the generated formula). A version tag exposes
`verified-release-candidates` only after the parser matrix and both package jobs
pass. Artifacts are candidates for review;
CI neither creates a tag nor publishes a release or a tap.

The source export normalizes archive metadata for stable source checksums. It
includes an explicit source-file list so extracted releases can rebuild and run
packaging tests without Git. This does not claim reproducible compiled binaries.

## Version and tag sequence

The published `v0.1.1` tag includes packaging; `v0.1.0` predates it. Keep published
tags at their original commits. Development changes belong in the Unreleased
changelog section. When preparing another release:

1. Choose a new version in VERSION and move the relevant Unreleased notes into
   its changelog section. Update versioned installation examples.
2. Merge the source and packaging changes into `main`; wait for the parser and
   Debian/Homebrew package jobs to pass.
3. From an up-to-date clean main checkout, create and push a new annotated tag
   matching `v` plus VERSION. Never reuse a published version for changed bytes.
4. Open that tag's **Build and test** run. Download `verified-release-candidates`
   after every required job passes, verify the checksums, and attach the extracted
   files to a GitHub Release for that same tag. Keep the asset filenames intact.

Ordinary branch/PR runs skip the final release-candidate collection job.

## Manual page

Debian and Homebrew packages install `coffin(1)`; read it with `man coffin`.
Source installs honor `MANDIR` (default `PREFIX/share/man`). Binary release
archives include `share/man/man1/coffin.1` beneath their top-level directory.
You can preview that file directly with `man ./share/man/man1/coffin.1`.
