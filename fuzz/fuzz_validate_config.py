"""
Atheris fuzz harness for validate_config.py.

Targets the two functions in validate_config.py that parse
attacker-influenceable strings without ever touching real credentials:

  - check_recipient_format(): regex-validates email address strings.
  - check_source_path(): resolves a path string and enforces that it stays
    inside the current working directory before touching the filesystem.

Both are pure/read-only with respect to the fuzzed input - check_source_path
only performs read-only fs calls (os.path.exists, os.access, Path.rglob) and
only after the containment check confirms the resolved path is inside cwd.

Run locally (Linux/macOS only - atheris ships no Windows wheel):
  pip install -r fuzz/requirements.txt
  python fuzz/fuzz_validate_config.py

Run bounded, as CI does:
  python fuzz/fuzz_validate_config.py -max_total_time=60
"""

import contextlib
import io
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import atheris

with atheris.instrument_imports():
    from validate_config import check_recipient_format, check_source_path


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())

    # Suppress the helpers' print() calls; stdout throughput would otherwise
    # dominate fuzzing speed and drown out real crash output.
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            check_recipient_format({"email_to": text})
        except Exception:
            raise  # an uncaught exception here is the bug we're hunting for

        try:
            check_source_path({"cx_source": text})
        except Exception:
            raise


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
