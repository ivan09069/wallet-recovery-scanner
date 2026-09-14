# Wallet artifact inventory

Read-only heuristic scanning for mnemonic-like text, 64-character hex values,
WIF-like strings, and JSON keystores. Output contains only paths, line numbers,
types, counts, and a completion summary. It never prints matched values or previews.
A match does not prove a valid wallet, mnemonic checksum, ownership, or balance.

Requires Bash and Python 3, with no external packages. Example:

```sh
bash proper_seed_scan.sh "$HOME/storage/downloads"
```

Pass one or more explicit, quoted paths. With no arguments, the scanner uses
`SCAN_DIRS` (shell-style quoted paths) or the legacy home/Android defaults.
Archives, binary files, symlinks, and files larger than 10 MiB are skipped.
Missing/unreadable locations are counted. No result file is written; the old
`RESULTS_FILE` variable is no longer used. Preserve any prior scan outputs locally;
they may contain sensitive values from earlier versions.

```sh
python3 -m unittest -v test_privacy.py
```
