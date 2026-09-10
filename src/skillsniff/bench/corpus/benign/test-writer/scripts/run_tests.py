import subprocess


def run(target):
    # An argument list never invokes a shell, so nothing needs quoting.
    return subprocess.run(['pytest', '-q', target], capture_output=True, check=False)
