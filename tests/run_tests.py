import subprocess
import os
from pathlib import Path
from typing import List, Tuple
import filecmp

def run_makefile():
    original_dir = os.getcwd()
    parent_dir = os.path.abspath(os.path.join(os.getcwd(), '..'))
    os.chdir(parent_dir) # move to parent directory

    try:
        subprocess.run(['make'], text=True, capture_output=True, check=True)
        print("Copilled successfully")
    except subprocess.CalledProcessError as e:
        print("Makefile failed!", e)
    finally: 
        os.chdir(original_dir)


# def get_pcap_files() -> Tuple[List[str], List[str]]:
def get_pcap_files() -> List[Path]:
    return Path(__file__).resolve().parent.glob('*.pcap')


def compare_files(out_file: Path, ref_file: Path):
    result = filecmp.cmp(out_file, ref_file)
    print(f"Comparing refrence file {ref_file.name} with {out_file.name} and the result is {result}")


def run_tests_verbose():
    parent_dir = os.path.abspath(os.path.join(os.getcwd(), '..'))
    dns_monitor_executable = os.path.join(parent_dir, 'dns-monitor')
    
    for pcap_file in Path(__file__).resolve().parent.glob('*.pcap'):
        res = subprocess.run([dns_monitor_executable, "-p", pcap_file, "-v"],
                            check=True,  
                            text=True,   
                            capture_output=True  
                            )
        output_file = pcap_file.with_suffix('.out')
        output_file.write_text(res.stdout)

        compare_files(output_file, output_file.with_suffix('.ref'))



if __name__ == "__main__":
    run_makefile()
    run_tests_verbose()
