#!/usr/bin/env bash
# wallet-recovery-scanner — proper seed phrase and private key scanner
# Scans for actual 12/24 word mnemonic sequences, hex private keys, and JSON keystores
# Unlike naive scanners that grep for single BIP39 words, this matches real patterns

set -euo pipefail

echo "=== WALLET RECOVERY SCANNER ==="
echo "Started: $(date -u)"
echo ""

# Configurable scan directories
DIRS="${SCAN_DIRS:-$HOME /sdcard/Download /sdcard/Documents}"
RESULTS="${RESULTS_FILE:-$HOME/scan_results.txt}"

# File exclusions
EXCLUDE_EXT='apk|so|dex|odex|art|oat|jar|png|jpg|jpeg|gif|mp4|mp3|aac|wav|zip|tar|gz|bz2|xz|rar|7z'

find_files() {
  find $DIRS -type f -size +0c -size -10M 2>/dev/null | \
    grep -vE "\.($EXCLUDE_EXT)$" | \
    sort -u
}

echo "=== 1. SEED PHRASE SCANNER ==="
echo "Scanning for 12+ consecutive lowercase words (BIP39 mnemonic pattern)..."
SEED_COUNT=0

find_files | while IFS= read -r f; do
  # Match lines with exactly 12, 15, 18, 21, or 24 lowercase words
  grep -nE '^[a-z]{3,8}( [a-z]{3,8}){11}( [a-z]{3,8}){0,12}$' "$f" 2>/dev/null | while IFS= read -r match; do
    # Count words to verify it's 12/15/18/21/24
    line="${match#*:}"
    wc=$(echo "$line" | wc -w)
    if [ "$wc" -eq 12 ] || [ "$wc" -eq 15 ] || [ "$wc" -eq 18 ] || [ "$wc" -eq 21 ] || [ "$wc" -eq 24 ]; then
      echo "SEED FOUND [$wc words]"
      echo "  FILE: $f"
      echo "  LINE: ${match%%:*}"
      echo "  PREVIEW: $(echo "$line" | cut -d' ' -f1-3)... $(echo "$line" | rev | cut -d' ' -f1-2 | rev)"
      echo "---"
    fi
  done
  # Also check for comma or newline separated mnemonics stored as JSON strings
  grep -noE '"[a-z]{3,8}( [a-z]{3,8}){11,23}"' "$f" 2>/dev/null | while IFS= read -r match; do
    echo "SEED IN STRING"
    echo "  FILE: $f"
    echo "  MATCH: ${match:0:60}..."
    echo "---"
  done
done

echo ""
echo "=== 2. HEX PRIVATE KEY SCANNER ==="
echo "Scanning for 0x + 64 hex character patterns..."

find_files | while IFS= read -r f; do
  grep -noE '0x[a-fA-F0-9]{64}' "$f" 2>/dev/null | while IFS= read -r match; do
    echo "HEX KEY FOUND"
    echo "  FILE: $f"
    echo "  POSITION: ${match%%:*}"
    echo "  KEY: ${match#*:}"
    echo "---"
  done
done

echo ""
echo "=== 3. RAW HEX KEY SCANNER (no 0x prefix) ==="
echo "Scanning for standalone 64-char hex strings in .env, .txt, .json, .csv files..."

find $DIRS -type f \( -name "*.env*" -o -name "*.txt" -o -name "*.json" -o -name "*.csv" -o -name "*.key" -o -name "*.secret" \) -size -1M 2>/dev/null | sort -u | while IFS= read -r f; do
  grep -noE '[^a-fA-F0-9][a-fA-F0-9]{64}[^a-fA-F0-9]' "$f" 2>/dev/null | while IFS= read -r match; do
    echo "RAW HEX KEY CANDIDATE"
    echo "  FILE: $f"
    echo "  MATCH: ${match:0:80}"
    echo "---"
  done
done

echo ""
echo "=== 4. WIF PRIVATE KEY SCANNER ==="
echo "Scanning for Bitcoin WIF format (5/K/L + 51 chars)..."

find_files | while IFS= read -r f; do
  grep -noE '[5KL][1-9A-HJ-NP-Za-km-z]{50,51}' "$f" 2>/dev/null | while IFS= read -r match; do
    echo "WIF KEY CANDIDATE"
    echo "  FILE: $f"
    echo "  MATCH: ${match#*:}"
    echo "---"
  done
done

echo ""
echo "=== 5. JSON KEYSTORE SCANNER ==="
echo "Scanning for encrypted keystore files..."

find $DIRS -type f \( -name "*.json" -o -name "*.keystore" -o -name "UTC--*" \) -size -1M 2>/dev/null | sort -u | while IFS= read -r f; do
  if grep -qlE '"(crypto|Crypto|ciphertext|kdf|cipher)"' "$f" 2>/dev/null; then
    addr=$(grep -oE '"address"\s*:\s*"[a-fA-F0-9]{40}"' "$f" 2>/dev/null | head -1 || echo "unknown")
    echo "KEYSTORE: $f"
    echo "  ADDRESS: $addr"
    echo "---"
  fi
done

echo ""
echo "=== 6. ENV FILE SCANNER ==="
echo "Scanning .env files for PRIVATE_KEY, SEED, MNEMONIC variables..."

find $DIRS -type f -name "*.env*" -size -1M 2>/dev/null | sort -u | while IFS= read -r f; do
  grep -inE '(PRIVATE_KEY|SEED|MNEMONIC|SECRET_KEY|WALLET_KEY)=' "$f" 2>/dev/null | while IFS= read -r match; do
    echo "ENV VAR"
    echo "  FILE: $f"
    echo "  MATCH: ${match:0:40}..."
    echo "---"
  done
done

echo ""
echo "=== SCAN COMPLETE ==="
echo "Finished: $(date -u)"
