# Independent verification runs

This directory contains independent validation runs of the Ed25519 curve verification program on different machines and operating systems.

Each subdirectory follows the naming convention:

`<os>-<arch>-<cpu>-<YYYY-MM>/`

and contains the run artifacts for one validation machine.

## Runs

| Run directory | Platform | Status | Notes |
|---|---|---:|---|
| `linux-x86_64-minipc-2026-03` | Linux / x86_64 / MiniPC | complete | Includes signed `hashes.txt.asc` |
| `macos-arm64-m1-2026-03` | macOS / arm64 / Apple M1 | complete | Includes signed `hashes.txt.asc` |

## Signature workflow
For each validation run, the manifest is signed with:

```bash
gpg --armor --detach-sign hashes.txt
```

which produces:

```text
hashes.txt.asc
```
