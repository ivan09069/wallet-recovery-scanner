import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SCANNER = Path(__file__).with_name('proper_seed_scan.sh')

class PrivacyTests(unittest.TestCase):
    def test_candidates_are_metadata_only_and_sources_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'space and newline\npath'; root.mkdir()
            values = ['0x' + 'a1'*32, 'b2'*32, 'K' + '1'*51, ' '.join(['alpha','bravo']*6)]
            file = root/'fixture.txt'; file.write_text('\n'.join(values))
            before = hashlib.sha256(file.read_bytes()).hexdigest()
            result = subprocess.run(['bash', str(SCANNER), str(root)], capture_output=True, text=True, check=True)
            for value in values:
                self.assertNotIn(value, result.stdout + result.stderr)
            records = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual({r['type'] for r in records[:-1]}, {'hex64_candidate','wif_candidate','mnemonic_candidate'})
            self.assertEqual(before, hashlib.sha256(file.read_bytes()).hexdigest())
            self.assertEqual(list(root.iterdir()), [file])

    def test_empty_missing_and_symlink_paths_do_not_read_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); target = root/'outside'; target.write_text('0x' + 'ab'*32)
            scan = root/'scan'; scan.mkdir(); (scan/'link').symlink_to(target)
            result = subprocess.run(['bash', str(SCANNER), str(scan), str(root/'missing')], capture_output=True, text=True, check=True)
            summary = json.loads(result.stdout)['summary']
            self.assertEqual(summary['candidate_records'], 0)
            self.assertEqual(summary['unavailable'], 1)

if __name__ == '__main__':
    unittest.main()
