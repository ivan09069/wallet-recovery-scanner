# wallet-recovery-scanner

Proper seed phrase and private key scanner for local filesystems. Designed for Termux on Android and Linux.

Unlike naive scanners that grep for individual BIP39 words (producing thousands of false positives), this tool scans for:

1. **Real mnemonic sequences** — 12/15/18/21/24 consecutive lowercase words
2. **Hex private keys** — `0x` + 64 hex characters
3. **Raw hex keys** — 64-char hex strings in config files
4. **Bitcoin WIF keys** — Base58 format (5/K/L prefix)
5. **JSON keystores** — Ethereum encrypted keystore files
6. **Environment variables** — `PRIVATE_KEY=`, `SEED=`, `MNEMONIC=` in `.env` files

## Usage

```bash
# Default: scans $HOME and /sdcard
bash proper_seed_scan.sh

# Custom directories
SCAN_DIRS="/path/to/scan" bash proper_seed_scan.sh

# Save results
bash proper_seed_scan.sh 2>&1 | tee ~/scan_results.txt
```

## Termux (Android)

```bash
pkg install -y git
git clone https://github.com/ivan09069/wallet-recovery-scanner.git
cd wallet-recovery-scanner
bash proper_seed_scan.sh 2>&1 | tee ~/scan_results.txt
```

## What it does NOT do

- Does not transmit any data
- Does not validate keys against any blockchain
- Does not derive addresses from found seeds
- Does not store or cache results anywhere except stdout

All scanning is local, read-only, and offline-safe.

## License

MIT
