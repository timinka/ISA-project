import subprocess
import os
from pathlib import Path
import filecmp

ROOT = Path(__file__).resolve().parent
MAKEFILE_DIR = ROOT.parent
EXECUTABLE = ROOT.parent / 'dns-monitor'

import unittest

class Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.chdir(MAKEFILE_DIR) # move to parent directory
        try:
            subprocess.run(['make'], text=True, capture_output=True, check=True)
        finally:
            os.chdir(ROOT)

    def dynamic_test(self, pcap_file: Path, use_verbose: bool):
        cmd = [EXECUTABLE, "-p", pcap_file]
        if use_verbose:
            cmd += ["-v"]
        res = subprocess.run(cmd, check=True, text=True, capture_output=True)
        output_file = pcap_file.with_suffix('.out')
        output_file.write_text(res.stdout)
        suffix = '.ref-verbose' if use_verbose else '.ref'
        result = filecmp.cmp(output_file, output_file.with_suffix(suffix=suffix))
        output_file.unlink()
        self.assertTrue(result)

if __name__ == '__main__':
        
    for pcap_file in ROOT.glob('*.pcap'):
        for use_verbose in [False, True]:
            name = f"test_{pcap_file.name}"
            if use_verbose:
                name += '_verbose'
            setattr(Test, name, lambda self: self.dynamic_test(pcap_file, use_verbose))

    unittest.main()

