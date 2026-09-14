#!/usr/bin/env python3
"""Read-only heuristic inventory. Never print candidate values or snippets."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys

MAX_BYTES = 10 * 1024 * 1024
EXCLUDED = {'.apk','.so','.dex','.odex','.art','.oat','.jar','.png','.jpg','.jpeg',
            '.gif','.mp4','.mp3','.aac','.wav','.zip','.tar','.gz','.bz2','.xz','.rar','.7z'}
HEX = re.compile(r'(?<![A-Za-z0-9])(?:0x)?[a-fA-F0-9]{64}(?![A-Za-z0-9])')
WIF = re.compile(r'(?<![A-Za-z0-9])(?:5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})(?![A-Za-z0-9])')
WORDS = re.compile(r'(?<![a-z])(?:[a-z]{3,8} ){11,23}[a-z]{3,8}(?![a-z])')

def safe_path(path):
    text = str(path)
    for pattern in (HEX, WIF, WORDS):
        text = pattern.sub('[candidate-redacted]', text)
    return text

def inspect(path):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BYTES:
            return []
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES or b'\0' in data:
        return []
    text = data.decode('utf-8', errors='replace')
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        for kind, pattern in [('hex64_candidate', HEX), ('wif_candidate', WIF), ('mnemonic_candidate', WORDS)]:
            matches = list(pattern.finditer(line))
            if kind == 'mnemonic_candidate':
                matches = [m for m in matches if len(m.group().split()) in (12,15,18,21,24)]
            if matches:
                findings.append({'path': safe_path(path), 'line': number, 'type': kind, 'count': len(matches)})
    try:
        obj = json.loads(text)
        crypto = obj.get('crypto', obj.get('Crypto')) if isinstance(obj, dict) else None
        if isinstance(crypto, dict) and 'ciphertext' in crypto and 'kdf' in crypto:
            findings.append({'path': safe_path(path), 'line': 1, 'type': 'keystore_candidate', 'count': 1})
    except (ValueError, RecursionError):
        pass
    return findings

def scan(roots):
    seen = set()
    counts = {'files_read': 0, 'candidate_records': 0, 'unavailable': 0}
    def emit(path):
        try:
            info = path.lstat()
            identity = (info.st_dev, info.st_ino)
            if not stat.S_ISREG(info.st_mode) or path.suffix.lower() in EXCLUDED or identity in seen:
                return
            if not 0 < info.st_size <= MAX_BYTES:
                return
            seen.add(identity)
            records = inspect(path)
            counts['files_read'] += 1
            for record in records:
                print(json.dumps(record, ensure_ascii=True))
                counts['candidate_records'] += 1
        except OSError:
            counts['unavailable'] += 1
    def onerror(error):
        counts['unavailable'] += 1
    for root in roots:
        root = Path(root).expanduser()
        if root.is_symlink():
            continue
        if root.is_file():
            emit(root)
        elif root.is_dir():
            for parent, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
                dirs[:] = [name for name in dirs if not (Path(parent)/name).is_symlink()]
                for name in files:
                    emit(Path(parent)/name)
        else:
            counts['unavailable'] += 1
    print(json.dumps({'status': 'completed', 'summary': counts, 'validation': 'heuristic_only; values suppressed'}))
    return 0

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('paths', nargs='*', help='Files or directories; quote paths containing spaces')
    args = parser.parse_args()
    roots = args.paths or shlex.split(os.environ['SCAN_DIRS']) if os.environ.get('SCAN_DIRS') else args.paths
    roots = roots or [str(Path.home()), '/sdcard/Download', '/sdcard/Documents']
    return scan(roots)

if __name__ == '__main__':
    sys.exit(main())
