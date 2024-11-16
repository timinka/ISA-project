import subprocess
import os
from pathlib import Path
import filecmp

ROOT = Path(__file__).resolve().parent
MAKEFILE_DIR = ROOT.parent
EXECUTABLE = ROOT.parent / 'dns-monitor'

class TestException(Exception):
    pass

def run_makefile():
    os.chdir(MAKEFILE_DIR) # move to parent directory
    try:
        subprocess.run(['make'], text=True, capture_output=True, check=True)
        print("Copiled successfully")
    except subprocess.CalledProcessError as e:
        raise TestException("Makefile failed!") from e
    finally: 
        os.chdir(ROOT)


def compare_files(out_file: Path, ref_file: Path):
    result = filecmp.cmp(out_file, ref_file)
    print(f"Comparing refrence file {ref_file.name} with {out_file.name} and the result is {result}")


def run_tests_verbose():
    for pcap_file in ROOT.glob('*.pcap'):
        try:
            cmd = [EXECUTABLE, "-p", pcap_file, "-v"]
            res = subprocess.run(cmd, check=True, text=True, capture_output=True)
            output_file = pcap_file.with_suffix('.out')
            output_file.write_text(res.stdout)
        except subprocess.CalledProcessError as e:
            print(f"Failed to execute '{' '.join(cmd)}':", e)
        else:
            compare_files(output_file, output_file.with_suffix('.ref'))



if __name__ == "__main__":
    try:
        run_makefile()
        run_tests_verbose()
    except TestException as e:
        print(e)
    except Exception as e:
        print("Something went wrong", e)
