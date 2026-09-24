#!/usr/bin/env python3
"""Shared ESP-IDF environment discovery for the TheLink build/flash scripts.

The scripts used to run the IDF tools with the first `python3` found on PATH.
That breaks when the interpreter (e.g. an MSYS2 Python) does not have the
ESP-IDF packages (esptool, pyserial, ...) installed. These helpers instead
locate the ESP-IDF Python virtual environment, which does.

`build_env()` additionally augments PATH with the ESP-IDF build tools (ninja,
cmake, git, the xtensa/riscv toolchains) and sets the key IDF_* variables so
idf.py works from any terminal without running the ESP-IDF export script
(export.ps1/export.bat) first.
"""

import os
import shutil
import subprocess
import sys

_WINDOWS = os.name == "nt"


def _is_env_dir(path):
    return (os.path.isfile(os.path.join(path, "Scripts", "python.exe")) or
            os.path.isfile(os.path.join(path, "bin", "python3")))


def _python_env_candidates():
    """Candidate search roots for the ESP-IDF Python environment."""
    candidates = []
    explicit = os.environ.get("IDF_PYTHON_ENV_PATH")
    if explicit:
        candidates.append(explicit)
    bases = []
    tools = os.environ.get("IDF_TOOLS_PATH")
    if tools:
        bases.append(tools)
    bases.append(os.path.join(os.path.expanduser("~"), ".espressif"))
    if _WINDOWS:
        for drive_path in (r"C:\Espressif", r"D:\Espressif"):
            bases.append(drive_path)
    for base in bases:
        pyenv = os.path.join(base, "python_env")
        if os.path.isdir(pyenv):
            candidates.append(pyenv)
    return candidates


def find_python_env():
    """Return the ESP-IDF Python environment dir, or None if not found."""
    for path in _python_env_candidates():
        if not os.path.isdir(path):
            continue
        if _is_env_dir(path):
            return path
        for name in sorted(os.listdir(path)):
            sub = os.path.join(path, name)
            if os.path.isdir(sub) and _is_env_dir(sub):
                return sub
    return None


def find_python():
    """Interpreter of the ESP-IDF Python env, else the running interpreter."""
    env = find_python_env()
    if env:
        for rel in ("Scripts", "python.exe"), ("bin", "python3"):
            exe = os.path.join(env, *rel)
            if os.path.isfile(exe):
                return exe
    return sys.executable


def find_idf_py():
    """Path to idf.py (prefer the real script over the Windows idf-exe wrapper)."""
    idf_path = os.environ.get("IDF_PATH")
    if idf_path:
        candidate = os.path.join(idf_path, "tools", "idf.py")
        if os.path.isfile(candidate):
            return candidate
    # Common install layouts when IDF_PATH is not exported.
    if _WINDOWS:
        frameworks = []
        for base in (os.environ.get("IDF_TOOLS_PATH"), r"C:\Espressif", r"D:\Espressif"):
            if base:
                frameworks.append(os.path.join(base, "frameworks"))
        for root in frameworks:
            if os.path.isdir(root):
                for name in sorted(os.listdir(root), reverse=True):
                    candidate = os.path.join(root, name, "tools", "idf.py")
                    if os.path.isfile(candidate):
                        return candidate
    return shutil.which("idf.py")


def find_idf_path():
    """Root of the ESP-IDF installation that find_idf_py() resolved to."""
    idf_py = find_idf_py()
    if idf_py:
        return os.path.dirname(os.path.dirname(idf_py))
    return os.environ.get("IDF_PATH")


def find_idf_invoke():
    """Command list to run idf.py with the ESP-IDF interpreter."""
    idf_script = find_idf_py()
    if not idf_script:
        return None
    if idf_script.lower().endswith(".py"):
        return [find_python(), idf_script]
    return [idf_script]  # native .exe wrapper, run directly


def _tools_roots():
    """Candidate ESP-IDF tool-installation roots, most-preferred first."""
    roots = []
    tools = os.environ.get("IDF_TOOLS_PATH")
    if tools:
        roots.append(tools)
    if _WINDOWS:
        roots.extend((r"C:\Espressif", r"D:\Espressif"))
    roots.append(os.path.join(os.path.expanduser("~"), ".espressif"))
    # de-duplicate, keep order (preference), keep only roots with a tools/ dir
    seen = set()
    ordered = []
    for r in roots:
        key = os.path.normcase(r)
        if key not in seen and os.path.isdir(os.path.join(r, "tools")):
            seen.add(key)
            ordered.append(r)
    return ordered


def _tool_dirs_for(exe_names, max_depth=3):
    """Directories containing one of exe_names, from the most-preferred root."""
    for root in _tools_roots():
        tools_dir = os.path.join(root, "tools")
        found = []
        for dirpath, dirnames, filenames in os.walk(tools_dir):
            depth = dirpath[len(tools_dir):].count(os.sep)
            if depth >= max_depth:
                dirnames[:] = []
                continue
            if any(name in filenames for name in exe_names):
                found.append(dirpath)
        if found:
            # Prefer deeper (more specific) dirs last so they end up first
            # after the insert(0, ...) ordering in build_env().
            found.sort(key=lambda p: p.count(os.sep))
            return found
    return []


def build_env():
    """
    Environment dict for subprocesses: current env plus PATH entries for the
    ESP-IDF build tools and the key IDF_* variables.

    This removes the need to run export.ps1/export.bat before the scripts.
    """
    env = os.environ.copy()
    additions = []

    pyenv = find_python_env()
    if pyenv:
        for rel in ("Scripts", "bin"):
            d = os.path.join(pyenv, rel)
            if os.path.isdir(d) and d not in additions:
                additions.append(d)
        env.setdefault("IDF_PYTHON_ENV_PATH", pyenv)

    idf_path = find_idf_path()
    if idf_path:
        env.setdefault("IDF_PATH", idf_path)
    for root in _tools_roots():
        env.setdefault("IDF_TOOLS_PATH", root)

    rom_elfs = _tool_dirs_for(
        ("esp32s3_rev0_rom.elf", "esp32_rev0_rom.elf"), max_depth=3)
    if rom_elfs:
        # export.ps1 sets ESP_ROM_ELF_DIR to the dir holding the *_rom.elf
        # files; cmake's gdbinit generation reads this env var.
        env.setdefault("ESP_ROM_ELF_DIR", rom_elfs[0])

    if _WINDOWS:
        additions += _tool_dirs_for(("ninja.exe", "ninja"))
        additions += _tool_dirs_for(("cmake.exe", "cmake"))
        additions += _tool_dirs_for(("git.exe",), max_depth=2)
    else:
        additions += _tool_dirs_for(("ninja",))
        additions += _tool_dirs_for(("cmake",))
    additions += _tool_dirs_for(
        ("xtensa-esp-elf-gcc", "xtensa-esp-elf-gcc.exe",
         "riscv32-esp-elf-gcc", "riscv32-esp-elf-gcc.exe"), max_depth=5)

    path = env.get("PATH", "")
    parts = path.split(os.pathsep) if path else []
    for d in additions:
        if d not in parts:
            parts.insert(0, d)
    # de-duplicate preserving order
    seen = set()
    ordered = []
    for p in parts:
        key = os.path.normcase(p)
        if key not in seen:
            seen.add(key)
            ordered.append(p)
    env["PATH"] = os.pathsep.join(ordered)
    return env


def run(cmd, **kwargs):
    """Run a command with the augmented ESP-IDF environment."""
    kwargs.setdefault("env", build_env())
    return subprocess.call(cmd, **kwargs)


def find_esptool():
    """
    Return the esptool invocation as a command list, or None.

    Preferred: `python -m esptool` inside the ESP-IDF Python env, where the
    esptool package is importable. Avoids the Windows `Scripts\\esptool.py`
    wrapper, which shadows the esptool package it is meant to launch.
    """
    env = find_python_env()
    if env is not None:
        for rel in ("Scripts", "python.exe"), ("bin", "python3"):
            python_exe = os.path.join(env, *rel)
            if os.path.isfile(python_exe):
                return [python_exe, "-m", "esptool"]

    # Fall back to esptool.py on PATH (e.g. after export.ps1 sets it up).
    script = shutil.which("esptool.py")
    if script:
        if script.lower().endswith(".py"):
            return [sys.executable, script]
        return [script]  # native .exe wrapper, run directly

    # Last resort: the esptool package importable by the current interpreter.
    if subprocess.call([sys.executable, "-c", "import esptool"],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL) == 0:
        return [sys.executable, "-m", "esptool"]
    return None