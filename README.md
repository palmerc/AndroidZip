# androidzip

A ZIP parser for Android APK malformation analysis. It reads both the Central Directory and Local File Header for every entry, surfaces discrepancies between them, and explains how Android handles each deviation versus how analysis tools typically behave.

## Background

APK files are ZIP archives. Android's ZIP parser (`libziparchive`) tolerates structural inconsistencies that standard tools do not, and vice versa. Malware authors exploit these gaps to craft APKs that install and run normally on-device while confusing static analysis tools (JADX, apktool, unzip).

Common techniques detected by this tool:

| Technique | Effect on analysis tools |
|---|---|
| Encryption flag in CD only | Tools prompt for a password that doesn't exist |
| Encryption flag in LFH only | Tools that read LFH refuse to extract |
| Unknown compression method | Tools reject the entry; Android treats it as STORED |
| Duplicate entry names | Tools see the first entry; Android loads the last |
| Directory/file name collision | Tools fail to extract; Android finds the file entry |
| CD/LFH filename mismatch | Sequential scanners index the wrong filename |
| CD/LFH size mismatch | Tools allocate wrong buffers or read past boundaries |

Each detected issue includes the Android source reference that defines the behavior.

## AOSP Source References

The following AOSP files define Android's authoritative ZIP behavior:

- **`platform/system/libziparchive/zip_archive.cc`** — entry table construction, GPBF/encryption handling, size bounding, duplicate resolution. Browse at [cs.android.com](https://cs.android.com/android/platform/superproject/+/main:system/libziparchive/zip_archive.cc).
- **`platform/system/libziparchive/zip_archive_private.h`** — `ZipEntry` struct definition.
- **`platform/libcore/ojluni/src/main/java/java/util/zip/ZipFile.java`** — Java-side ZIP used by the package manager.
- **`platform/frameworks/base/libs/androidfw/ZipFileRO.cpp`** — asset loading via `AssetManager`.
- **`platform/frameworks/base/core/java/android/content/pm/PackageParser.java`** — APK entry name resolution during install.

## Building

Requires Go 1.22 or later.

```sh
make          # vet + build
make build    # binary only → ./androidzip
make install  # installs to $GOPATH/bin
make test     # run tests
make clean    # remove binary
```

## Usage

```sh
# Human-readable report (exits 0 if clean, 2 if issues found)
androidzip suspicious.apk

# JSON report (pipe into jq, SIEM, etc.)
androidzip --json suspicious.apk | jq .

# Use exit code in CI
androidzip app.apk || echo "malformation detected"
```

### Example output

```
AndroidZip Malformation Report
────────────────────────────────────────────────────────────────────────
File:    teabot_sample.apk
Entries: 18
Issues:  3

────────────────────────────────────────────────────────────────────────
[classes.dex]

  CRITICAL  encryption_mismatch
  Description:
    The encryption flag (GPBF bit 0) differs between the Central
    Directory and Local File Header. The data is not actually encrypted.
  Android behavior:
    libziparchive populates ZipEntry.gpbf from the Central Directory.
    The device installs the file without decryption. Analysis tools
    that trust the opposing header stall, prompt for a password, or
    refuse to extract.
  AOSP source:
    platform/system/libziparchive: zip_archive.cc, OpenArchiveInternal() /
    FindEntry()
  Values:  cd=false                lfh=true

[classes.dex]

  CRITICAL  duplicate_name
  Description:
    Two or more Central Directory entries share the same filename.
  Android behavior:
    libziparchive's hash table stores the last entry for any given
    name. Android loads the final duplicate. Tools that use the first
    entry (e.g. unzip) will analyse a decoy payload while Android runs
    the real one.
  AOSP source:
    platform/system/libziparchive: zip_archive.cc, OpenArchiveInternal()
    — entries are inserted into a hash map; collisions overwrite the
    prior entry
```

## Project layout

```
androidzip/
  main.go           entry point, flag parsing, report output
  zip/
    structures.go   ZIP binary structs, GPBF constants, Issue types
    reader.go       two-pass parser: EOCD → CD → LFH → diff
    report.go       report assembly, text and JSON rendering, AOSP references
  Makefile
```

## Limitations / Roadmap

- No known outstanding limitations.
