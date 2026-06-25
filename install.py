#!/usr/bin/env python
"""One-shot setup for a fresh clone of forensic-investigator.

Creates the core virtualenv and installs dependencies, seeds a .env, and (optionally)
sets up the isolated Volatility venv for memory analysis. Cross-platform (Windows /
macOS / Linux), stdlib-only, idempotent — safe to re-run.

    python install.py              # core tool + Volatility memory analysis (default)
    python install.py --no-memory  # core tool only (skip Volatility)

After it finishes: put your API key in .env, then
    python main.py investigate "PATH/TO/EVIDENCE" --case-id test --only Psh
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
IS_WIN = os.name == "nt"
MIN_PY = (3, 10)


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if IS_WIN else "bin/python")


def _vol_exe(venv: Path) -> str:
    return str((venv / ("Scripts/vol.exe" if IS_WIN else "bin/vol")))


def _run(cmd: list[str]) -> None:
    print("    $ " + " ".join(cmd))
    subprocess.run(cmd, check=True)


def _make_venv(venv: Path, requirements: Path, label: str) -> None:
    if venv.exists():
        print(f"[*] {label} venv already exists ({venv.name}); installing/updating deps.")
    else:
        print(f"[*] Creating {label} venv ({venv.name}) ...")
        _run([sys.executable, "-m", "venv", str(venv)])
    vpy = _venv_python(venv)
    _run([str(vpy), "-m", "pip", "install", "--quiet", "--upgrade", "pip"])
    _run([str(vpy), "-m", "pip", "install", "-r", str(requirements)])


def main() -> int:
    ap = argparse.ArgumentParser(description="Set up forensic-investigator after a fresh clone.")
    ap.add_argument("--no-memory", action="store_true",
                    help="skip the .venv-vol Volatility environment "
                         "(memory analysis is set up by default)")
    args = ap.parse_args()

    if sys.version_info < MIN_PY:
        print(f"error: Python {MIN_PY[0]}.{MIN_PY[1]}+ required; you have "
              f"{sys.version_info.major}.{sys.version_info.minor}.", file=sys.stderr)
        return 1

    print(f"forensic-investigator setup  (python {sys.version.split()[0]}, {'Windows' if IS_WIN else 'POSIX'})\n")

    # 1. Core venv + dependencies.
    _make_venv(ROOT / ".venv", ROOT / "requirements.txt", "core")

    # 2. Seed .env from the template (never overwrite an existing one).
    env, example = ROOT / ".env", ROOT / ".env.example"
    if env.exists():
        print("[*] .env already present; leaving it untouched.")
    elif example.exists():
        shutil.copyfile(example, env)
        print("[*] Created .env from .env.example  ->  add your ANTHROPIC_API_KEY to it.")
    else:
        print("[!] No .env.example found; create a .env with ANTHROPIC_API_KEY=... yourself.")

    # 3. Optional: Volatility venv for memory analysis.
    memory_note = ""
    if not args.no_memory:
        _make_venv(ROOT / ".venv-vol", ROOT / "requirements-memory.txt", "memory (Volatility)")
        # config.yaml ships with the Windows vol_cmd; tell POSIX users to adjust it.
        if not IS_WIN:
            memory_note = ("\n  - config/config.yaml ships with a Windows vol_cmd. Set it to:\n"
                           "      memory:\n        vol_cmd: [\".venv-vol/bin/vol\"]")
        else:
            memory_note = "\n  - memory is ready (config.yaml's default vol_cmd matches)."
    else:
        memory_note = ("\n  - memory analysis SKIPPED (--no-memory). Re-run without that flag, or set "
                       "memory.enabled: false in config/config.yaml to silence Volatility errors.")

    act = r".venv\Scripts\Activate.ps1" if IS_WIN else "source .venv/bin/activate"
    print("\n" + "=" * 64)
    print("Setup complete. Next steps:")
    print(f"  1. Add your API key to .env (ANTHROPIC_API_KEY=...).")
    print(f"  2. Activate the env:  {act}")
    print(f"  3. Run:  python main.py investigate \"PATH/TO/EVIDENCE\" --case-id test --only Psh")
    print("  (memory)" + memory_note)
    print("=" * 64)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
