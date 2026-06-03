"""Build helucryptic into a standalone executable with PyInstaller.

The active `.env` is bundled alongside the binary so `config.py` can read it at
runtime via ``sys._MEIPASS``. Run from the project root:

    python build.py            # build with the current interpreter
    python build.py --fresh    # build from a clean, dedicated venv (recommended)

`--fresh` creates `.build-venv` containing ONLY requirements.txt + PyInstaller,
then builds from it. This is the single biggest lever on binary size: building
from a shared/kitchen-sink environment risks PyInstaller's hooks dragging in
unrelated heavyweight packages (torch, PyQt5, transformers, …).

NOTE: bundling `.env` embeds whatever secrets it contains into the distributed
binary. The server password is only a *real* gate because the signaling server
validates it (see server.py) — never rely on the bundled copy being secret.
"""
import os
import subprocess
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

ROOT = Path(__file__).resolve().parent
BUILD_VENV = ROOT / ".build-venv"

# Native-heavy packages whose binaries/data PyInstaller's auto-analysis can miss.
COLLECT_ALL = (
    "aiortc", "av", "flet", "cryptography", "pyseto", "sounddevice", "mss",
    "PIL", "qrcode",
)

# Heavyweight packages helucryptic never imports. Excluding them is pure
# insurance so a polluted environment can't leak them into the bundle. (Harmless
# if absent.) fastapi/uvicorn are server-only; the GUI client doesn't import them.
EXCLUDES = (
    "torch", "torchvision", "torchaudio", "tensorflow", "transformers",
    "pandas", "scipy", "sklearn", "scikit-learn", "matplotlib", "numba",
    "llvmlite", "sympy", "PyQt5", "PyQt6", "PySide2", "PySide6", "cv2",
    "pygame", "IPython", "jupyter", "notebook", "pytest", "sphinx",
    "googleapiclient", "langchain", "sherpa_onnx", "debugpy", "jedi",
    "tkinter", "fastapi", "uvicorn", "starlette",
)


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts" if os.name == "nt" else "bin") / (
        "python.exe" if os.name == "nt" else "python")


def _make_fresh_venv() -> Path:
    """Create/refresh a clean venv with only the app's deps + PyInstaller."""
    py = _venv_python(BUILD_VENV)
    if not py.exists():
        print(f"[INFO] Creating clean build venv at {BUILD_VENV} …")
        subprocess.run([sys.executable, "-m", "venv", str(BUILD_VENV)], check=True)
    print("[INFO] Installing requirements + PyInstaller into the build venv …")
    subprocess.run([str(py), "-m", "pip", "install", "--upgrade", "pip"], check=True)
    subprocess.run([str(py), "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")], check=True)
    subprocess.run([str(py), "-m", "pip", "install", "pyinstaller"], check=True)
    return py


def _clean_build_dir() -> None:
    build_dir = ROOT / "build"
    if not build_dir.exists():
        return
    print(f"[INFO] Cleaning existing build directory: {build_dir}")
    import shutil
    import stat
    import time
    for root, dirs, files in os.walk(build_dir):
        for d in dirs:
            try:
                os.chmod(os.path.join(root, d), stat.S_IWRITE)
            except Exception:
                pass
        for f in files:
            try:
                os.chmod(os.path.join(root, f), stat.S_IWRITE)
            except Exception:
                pass
    for attempt in range(5):
        try:
            shutil.rmtree(build_dir)
            return
        except Exception:
            time.sleep(0.5)
    print("[WARN] Could not clean build directory completely. Continuing anyway...")


def main(argv: list[str]) -> int:
    _clean_build_dir()
    fresh = "--fresh" in argv
    py = _make_fresh_venv() if fresh else Path(sys.executable)

    env_file = ROOT / ".env"
    if load_dotenv and env_file.exists():
        load_dotenv(env_file)

    url = os.getenv("HELUCRYPTIC_SIGNALING_URL")
    if not env_file.exists():
        print("[WARN] No .env found — building with built-in defaults. "
              "Copy .env.example to .env to customise.")
    else:
        print(f"[INFO] Building helucryptic (signaling: {url or 'default'})")

    datas = [("tracks", "tracks"), ("icon.ico", ".")]
    if env_file.exists():
        datas.append((".env", "."))

    cmd = [
        str(py), "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--onefile", "--noconsole",
        "--name", "Helucryptic",
        "--icon", "icon.ico",
    ]
    for src, dest in datas:
        cmd += ["--add-data", f"{src}{os.pathsep}{dest}"]
    for pkg in COLLECT_ALL:
        cmd += ["--collect-all", pkg]
    for mod in EXCLUDES:
        cmd += ["--exclude-module", mod]
    cmd.append("main.py")

    print("->", " ".join(cmd))
    return subprocess.run(cmd, cwd=ROOT).returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
