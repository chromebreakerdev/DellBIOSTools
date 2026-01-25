import sys
if sys.stdout is None:
    pass
else:
    sys.stdout = open("nul", "w")
    sys.stderr = open("nul", "w")


import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

import re
import os
import sys
import importlib
import binascii
import subprocess
import hashlib
import ctypes
import shlex
from collections import defaultdict
from typing import List, Dict, Optional
from datetime import datetime



# -------------------------------------------------
# Pillow (safe for PyInstaller EXE)
# -------------------------------------------------
try:
    from PIL import Image, ImageTk
except ImportError:
    Image = None
    ImageTk = None

# ==========================================================
# Application base path + vendor folder support
# ==========================================================

def app_base_path():
    """
    Resolve base directory for both .pyw and PyInstaller EXE.
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = app_base_path()

VENDOR_DIR = os.path.join(BASE_DIR, "vendor")

if VENDOR_DIR not in sys.path:
    sys.path.insert(0, VENDOR_DIR)

# ==========================================================
# Logging helper
# ==========================================================

def log(message: str):
    """
    Central logging helper.
    Safe to call before or after GUI init.
    """
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")

    try:
        if "app" in globals() and hasattr(app, "log_text"):
            app.log_text.configure(state=tk.NORMAL)
            app.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
            app.log_text.configure(state=tk.DISABLED)
            app.log_text.see(tk.END)
    except Exception:
        pass

# ==========================================================
# PyInstaller-safe runtime paths + vendor import support
# ==========================================================

def runtime_base_dir():
    """
    Returns the directory where bundled resources live.
    - PyInstaller onefile/onedir: sys._MEIPASS
    - Normal .py/.pyw execution: this file's directory
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


RUNTIME_BASE = runtime_base_dir()


def resource_path(relative_path):
    """
    Get absolute path to a bundled resource.
    Works for source and PyInstaller EXE.
    """
    return os.path.join(RUNTIME_BASE, relative_path)


# ----------------------------------------------------------
# Ensure vendor imports work (CRITICAL for PFS extractor)
# ----------------------------------------------------------

# Add the *parent* of vendor to sys.path
if RUNTIME_BASE not in sys.path:
    sys.path.insert(0, RUNTIME_BASE)

# Add vendor itself for legacy absolute imports
VENDOR_DIR = os.path.join(RUNTIME_BASE, "vendor")
if VENDOR_DIR not in sys.path:
    sys.path.insert(0, VENDOR_DIR)


# ----------------------------------------------------------
# Optional biosutilities shim (EXE-safe)
# ----------------------------------------------------------
try:
    import biosutilities  # noqa: F401
except ImportError:
    try:
        real_pkg = importlib.import_module("vendor.biosutilities")
        sys.modules["biosutilities"] = real_pkg
    except ImportError:
        pass


# ----------------------------------------------------------
# PFS extractor import (FAIL LOUDLY during testing)
# ----------------------------------------------------------
from vendor.dell_pfs_extract import run_pfs_extract

# ========================================================================



################################################################################
# COMMON HELPERS (Windows + WinPE aware)
################################################################################

def get_exe_dir():
    return os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) \
        else os.path.dirname(os.path.abspath(__file__))

BASE_DIR = get_exe_dir()

def is_winpe():
    try:
        if os.environ.get("SystemDrive", "").upper() == "X:":
            return True
        p = subprocess.run(
            ["reg", "query", r"HKLM\SYSTEM\ControlSet001\Control\MiniNT"],
            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        return p.returncode == 0
    except Exception:
        return False

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def ensure_admin_windows():
    # WinPE runs as SYSTEM; on full Windows, elevate if not admin
    if is_winpe() or is_admin():
        return
    script = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
    raise SystemExit

def log_root():
    return r"X:\AssetLogs" if is_winpe() \
        else os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "DellBIOSTools", "AssetLogs")

_LOGFILE = None
def log(msg: str):
    """Minimal logger used by Asset tab."""
    global _LOGFILE
    root = log_root()
    os.makedirs(root, exist_ok=True)
    if _LOGFILE is None:
        _LOGFILE = os.path.join(root, f"AssetRun_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    line = f"{datetime.utcnow().isoformat(timespec='seconds')}Z  {msg}"
    try:
        with open(_LOGFILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line)

# Normalize returned asset strings (strip noise/placeholder values)
def _normalize_asset(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    bads = {
        "none", "n/a", "na", "unknown", "to be filled by o.e.m.", "to be filled by oem",
        "system manufactured", "not provided", "no asset tag"
    }
    if s.lower() in bads:
        return ""
    return s

################################################################################
# PowerShell CIM/WMI (READ path only — Win11-safe, no dcmscli)
################################################################################

def _find_powershell_exe() -> Optional[str]:
    """
    Return a usable PowerShell host:
      - Windows PowerShell (System32 or Sysnative)
      - PowerShell 7 (pwsh.exe) if present
      - Or PATH
    """
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    candidates = [
        os.path.join(system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
        os.path.join(system_root, "Sysnative", "WindowsPowerShell", "v1.0", "powershell.exe"),
        os.path.join(r"C:\Program Files\PowerShell", "7", "pwsh.exe"),
        os.path.join(r"C:\Program Files\PowerShell", "7-preview", "pwsh.exe"),
        os.path.join(r"C:\Program Files (x86)\PowerShell", "7", "pwsh.exe"),
        "pwsh.exe", "powershell.exe", "pwsh", "powershell",
    ]
    for path in candidates:
        try:
            if os.path.sep in path:
                if os.path.exists(path):
                    return path
            else:
                p = subprocess.run(
                    [path, "-NoProfile", "-NoLogo", "-Command", "$PSVersionTable.PSEdition"],
                    capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
                )
                if p.returncode == 0:
                    return path
        except Exception:
            continue
    return None

def _run_powershell(ps_path: str, script: str):
    exe = os.path.basename(ps_path).lower()
    if "pwsh" in exe:
        cmd = [ps_path, "-NoProfile", "-NoLogo", "-Command", script]
    else:
        cmd = [ps_path, "-NoProfile", "-NoLogo", "-ExecutionPolicy", "Bypass", "-Command", script]
    return subprocess.run(cmd, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)

def get_asset_tag_cim_only() -> str:
    """
    Read AssetTag using PowerShell CIM first, then legacy WMI.
    Avoids Dell WMI provider and dcmscli (Win11-friendly).

    Returns:
        - non-empty normalized tag string if one exists
        - "" (empty string) if CIM/WMI ran successfully but tag is actually blank/placeholder
        - raises RuntimeError only when the query itself fails
    """
    ps = _find_powershell_exe()
    if not ps:
        raise RuntimeError("PowerShell host not found (powershell.exe/pwsh.exe).")
    scripts = [
        # CIM (modern)
        "$ErrorActionPreference='Stop'; "
        "$t=(Get-CimInstance -ClassName Win32_SystemEnclosure | "
        "Select-Object -ExpandProperty SMBIOSAssetTag); if ($t) { $t }",
        # Legacy WMI
        "$ErrorActionPreference='Stop'; "
        "$t=(Get-WmiObject -Class Win32_SystemEnclosure).SMBIOSAssetTag; if ($t) { $t }",
    ]
    last_err = None
    saw_ok = False

    for sc in scripts:
        try:
            p = _run_powershell(ps, sc)
            out = (p.stdout or "").strip()

            # Script executed successfully, even if the output is blank
            if p.returncode == 0:
                saw_ok = True
                if out:
                    tag = _normalize_asset(out.splitlines()[0])
                    if tag:
                        return tag
            else:
                if (p.stderr or "").strip():
                    last_err = (p.stderr or "").strip()
        except Exception as e:
            last_err = str(e)

    # If at least one script ran OK but we never got a real tag, treat as "no tag set"
    if saw_ok and not last_err:
        return ""

    raise RuntimeError(f"WMI/CIM AssetTag read failed. {last_err or 'No output.'}")

################################################################################
# —— CCTK discovery (WRITE path; also usable as read fallback) ——
################################################################################

REQUIRED_DLLS = ["BIOSIntf.dll"]  # minimal required; others vary by build

def candidate_cctk_paths():
    paths = []

    # --------------------------------------------------
    # 1) PyInstaller onefile bundle (MOST IMPORTANT)
    # --------------------------------------------------
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        paths.extend([
            os.path.join(sys._MEIPASS, "vendor", "cctk", "x86_64", "cctk.exe"),
            os.path.join(sys._MEIPASS, "vendor", "cctk", "X86_64", "cctk.exe"),
        ])

    # --------------------------------------------------
    # 2) Existing logic (UNCHANGED)
    # --------------------------------------------------

    # Root-of-drive vendor drop (supports \vendor\cctk\x86_64)
    maybe_root = os.path.abspath(r"\vendor\cctk\x86_64\cctk.exe")
    maybe_root_alt = os.path.abspath(r"\vendor\cctk\X86_64\cctk.exe")

    # Env override
    env_dir = os.environ.get("DELL_CCTK_DIR", "")
    env_exe = os.path.join(env_dir, "cctk.exe") if env_dir else ""

    paths.extend([
        maybe_root,
        maybe_root_alt,
        env_exe,
        os.path.join(BASE_DIR, "vendor", "cctk", "x86_64", "cctk.exe"),
        os.path.join(BASE_DIR, "vendor", "cctk", "X86_64", "cctk.exe"),
        os.path.join(BASE_DIR, "cctk", "x86_64", "cctk.exe"),
        os.path.join(BASE_DIR, "cctk.exe"),
        r"X:\Windows\System32\cctk\X86_64\cctk.exe",
        r"C:\Program Files (x86)\Dell\Command Configure\X86_64\cctk.exe",
        r"C:\Program Files\Dell\Command Configure\X86_64\cctk.exe",
    ])

    return paths


def find_cctk_bundle():
    tried = []
    for exe in candidate_cctk_paths():
        if exe and os.path.exists(exe):
            folder = os.path.dirname(exe)
            missing = [d for d in REQUIRED_DLLS if not os.path.exists(os.path.join(folder, d))]
            if missing:
                tried.append((exe, f"missing {', '.join(missing)}"))
                continue
            os.environ["PATH"] = folder + os.pathsep + os.environ.get("PATH", "")
            return exe, folder
        elif exe:
            tried.append((exe, "not found"))
    detail = "\n".join(f"  {p} -> {why}" for p, why in tried)
    raise FileNotFoundError(
        "cctk.exe bundle not found/invalid.\n" + detail +
        "\nExpected cctk.exe next to BIOSIntf.dll (e.g., \\vendor\\cctk\\x86_64\\)"
    )

def ensure_hapi_present(cctk_folder_hint=None):
    """
    WinPE: run WinPE HAPI installer if found.
    Windows: try to start HAPI; if installer exists, run it.
    Strict CCTK prerequisite handling only (no WMI/CIM).
    """
    candidates = []
    if cctk_folder_hint:
        base = os.path.abspath(os.path.join(cctk_folder_hint, ".."))
        candidates += [
            os.path.join(base, "HAPI", "WinPE", "x64", "InstallHAPI.bat"),
            os.path.join(base, "HAPI", "Win", "x64", "InstallHAPI.bat"),
        ]
    candidates += [
        os.path.join(BASE_DIR, "vendor", "cctk", "HAPI", "WinPE", "x64", "InstallHAPI.bat"),
        os.path.join(BASE_DIR, "vendor", "cctk", "HAPI", "Win", "x64", "InstallHAPI.bat"),
        r"X:\Windows\System32\cctk\HAPI\WinPE\x64\InstallHAPI.bat",
    ]

    def _try_start_hapi():
        for svc in ("HAPI", "hapi", "dchserv"):
            try:
                subprocess.run(["sc", "start", svc], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception:
                pass

    if is_winpe():
        for bat in candidates:
            if os.path.exists(bat) and "WinPE" in bat:
                log(f"Installing WinPE HAPI via {bat}")
                subprocess.run([bat], creationflags=subprocess.CREATE_NO_WINDOW)
                break
        _try_start_hapi()
    else:
        _try_start_hapi()
        for bat in candidates:
            if os.path.exists(bat) and ("Win\\x64" in bat.replace("/", "\\") or "HAPI\\Win\\x64" in bat.replace("/", "\\")):
                log(f"Installing Windows HAPI via {bat}")
                subprocess.run([bat], creationflags=subprocess.CREATE_NO_WINDOW)
                _try_start_hapi()
                break

def run_cctk(cctk_path, args):
    folder = os.path.dirname(cctk_path)
    cmd = [cctk_path] + args
    log("CCTK: " + " ".join(shlex.quote(a) for a in cmd))
    try:
        os.environ["PATH"] = folder + os.pathsep + os.environ.get("PATH", "")
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=folder,  # ensure DLLs (BIOSIntf, etc.) resolve
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except Exception as e:
        return 1, "", f"Error: {e}"

def _parse_asset_from_text(s: str) -> str:
    if not s:
        return ""
    lines = [ln.strip() for ln in s.splitlines() if ln.strip()]
    for ln in lines:
        low = ln.lower()
        if low.startswith("asset="):
            return ln.split("=", 1)[1].strip()
        if low.startswith("asset tag=") or low.startswith("assettag="):
            return ln.split("=", 1)[1].strip()
    if len(lines) == 1 and "=" not in lines[0]:
        return lines[0].strip()
    return ""

def get_asset_tag_cctk(cctk_path):
    rc, out, err = run_cctk(cctk_path, ["--asset"])
    asset = _parse_asset_from_text(out) or _parse_asset_from_text(err)
    asset = _normalize_asset(asset)

    # Treat rc == 0 as success even if the tag is blank/placeholder.
    if rc == 0:
        return asset  # may be "" if no tag is actually set

    raise RuntimeError(
        "CCTK --asset failed.\n"
        f"Return code: {rc}\n\nSTDOUT:\n{out}\n\nSTDERR:\n{err}\n\n"
        "Hints:\n"
        " • Ensure BIOSIntf.dll is next to cctk.exe\n"
        " • Install/Start HAPI (WinPE: HAPI\\WinPE\\x64\\InstallHAPI.bat)\n"
        " • Run as Administrator"
    )

def set_asset_tag(cctk_path, new_tag, setup_pwd=None):
    # Allow empty string to CLEAR the tag (CCTK --asset=).
    if new_tag is None:
        raise ValueError("new_tag must be a string; use '' to clear.")
    args = [f"--asset={new_tag}"]
    if setup_pwd:
        args.append(f"--valsetuppwd={setup_pwd}")
    rc, out, err = run_cctk(cctk_path, args)
    if rc != 0:
        raise RuntimeError(
            "CCTK --asset set failed.\n"
            f"Return code: {rc}\n\nSTDOUT:\n{out}\n\nSTDERR:\n{err}"
        )
    return True

def fast_restart_to_bios():
    subprocess.run(["shutdown", "/r", "/fw", "/t", "0"], creationflags=subprocess.CREATE_NO_WINDOW)

################################################################################
# PART 1: BIOS Unlocker Tool Functions
################################################################################

def convert_hex_to_bytes(hex_string):
    try:
        return bytes.fromhex(hex_string)
    except binascii.Error:
        return None

def bytes_to_hex_string(byte_array):
    return byte_array.hex().upper()

def find_intel_signature(data, signature_bytes):
    for i in range(min(0x1000, len(data) - len(signature_bytes))):
        if data[i:i+len(signature_bytes)] == signature_bytes:
            return i
    return -1

def find_pattern_matches(data, pattern_regex):
    matches = []
    max_offset = min(0x160000, len(data))
    for i in range(max_offset):
        chunk_size = min(20, len(data) - i)
        if chunk_size < 6:
            continue
        chunk = data[i:i+chunk_size]
        hex_chunk = bytes_to_hex_string(chunk)
        match = re.match(pattern_regex, hex_chunk)
        if match:
            matches.append(i)
    return matches

################################################################################
# PART 2: Dell Password Generator Functions
################################################################################

md5magic = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]

md5magic2 = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039
]

rotationTable = [
    [7, 12, 17, 22],
    [5, 9, 14, 20],
    [4, 11, 16, 23],
    [6, 10, 15, 21]
]

initialData = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

def mask32(x: int) -> int:
    return x & 0xFFFFFFFF

def rol(x: int, bits: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << bits) & 0xFFFFFFFF) | (x >> (32 - bits))

def encF1(num1: int, num2: int) -> int:
    return (num1 + num2) & 0xFFFFFFFF

def encF1N(num1: int, num2: int) -> int:
    return (num1 - num2) & 0xFFFFFFFF

def encF2(num1: int, num2: int, num3: int) -> int:
    return ((num3 ^ num2) & num1) ^ num3

def encF2N(num1: int, num2: int, num3: int) -> int:
    return encF2(num1, num2, (~num3) & 0xFFFFFFFF)

def encF3(num1: int, num2: int, num3: int) -> int:
    return ((num1 ^ num2) & num3) ^ num2

def encF4(num1: int, num2: int, num3: int) -> int:
    return (num2 ^ num1) ^ num3

def encF4N(num1: int, num2: int, num3: int) -> int:
    return encF4(num1, (~num2) & 0xFFFFFFFF, num3)

def encF5(num1: int, num2: int, num3: int) -> int:
    return (num1 | ((~num3) & 0xFFFFFFFF)) ^ num2

def encF5N(num1: int, num2: int, num3: int) -> int:
    return encF5((~num1) & 0xFFFFFFFF, num2, num3)

class Tag595BEncoder:
    f1 = staticmethod(encF1N)
    f2 = staticmethod(encF2N)
    f3 = staticmethod(encF3)
    f4 = staticmethod(encF4N)
    f5 = staticmethod(encF5N)
    md5table = md5magic
    def __init__(self, encBlock: List[int]):
        self.encBlock = encBlock
        self.encData = self.initialData()
        self.A = self.encData[0]
        self.B = self.encData[1]
        self.C = self.encData[2]
        self.D = self.encData[3]
    @classmethod
    def encode(cls, encBlock: List[int]) -> List[int]:
        obj = cls(encBlock); obj.makeEncode(); return obj.result()
    def makeEncode(self) -> None:
        for i in range(64):
            which = i >> 4
            if which == 0:
                t = self.calculate(self.f2, (i & 15), i)
            elif which == 1:
                t = self.calculate(self.f3, ((i*5+1)&15), i)
            elif which == 2:
                t = self.calculate(self.f4, ((i*3+5)&15), i)
            else:
                t = self.calculate(self.f5, ((i*7)&15), i)
            self.A, self.D, self.C = self.D, self.C, self.B
            shift = rotationTable[which][(i & 3)]
            self.B = mask32(self.B + rol(t, shift))
        self.incrementData()
    def initialData(self) -> List[int]:
        return initialData[:]
    def calculate(self, func, key1: int, key2: int) -> int:
        tmp = func(self.B, self.C, self.D)
        combined = (self.md5table[key2] + self.encBlock[key1]) & 0xFFFFFFFF
        return (self.A + self.f1(tmp, combined)) & 0xFFFFFFFF
    def incrementData(self) -> None:
        self.encData[0] = mask32(self.encData[0] + self.A)
        self.encData[1] = mask32(self.encData[1] + self.B)
        self.encData[2] = mask32(self.encData[2] + self.C)
        self.encData[3] = mask32(self.encData[3] + self.D)
    def result(self) -> List[int]:
        return [mask32(x) for x in self.encData]

class TagD35BEncoder(Tag595BEncoder):
    f1 = staticmethod(encF1)
    f2 = staticmethod(encF2)
    f3 = staticmethod(encF3)
    f4 = staticmethod(encF4)
    f5 = staticmethod(encF5)

class Tag1D3BEncoder(Tag595BEncoder):
    def makeEncode(self) -> None:
        for j in range(21):
            self.A |= 0x97; self.B ^= 0x8
            self.C |= (0x60606161 - j) & 0xFFFFFFFF
            self.D ^= (0x50501010 + j) & 0xFFFFFFFF
            super().makeEncode()

class Tag1F66Encoder(Tag595BEncoder):
    md5table = md5magic2
    def makeEncode(self) -> None:
        for j in range(17):
            self.A |= 0x100097; self.B ^= 0xA0008
            self.C |= (0x60606161 - j) & 0xFFFFFFFF
            self.D ^= (0x50501010 + j) & 0xFFFFFFFF
            for i in range(64):
                which = i>>4
                if which == 0: t = self.calculate(self.f2, (i &15), (i+16)&0xFFFFFFFF)
                elif which == 1: t = self.calculate(self.f3, ((i*5+1)&15), (i+32)&0xFFFFFFFF)
                elif which == 2:
                    offset = i -2*(i &12)+12
                    t = self.calculate(self.f4, ((i*3+5)&15), offset)
                else:
                    offset = 2*(i &3) - (i &15)+12
                    t = self.calculate(self.f5, ((i*7)&15), offset)
                self.A, self.D, self.C = self.D, self.C, self.B
                shift = rotationTable[which][(i &3)]
                self.B = mask32(self.B + rol(t, shift))
            self.incrementData()
        for j in range(21):
            self.A |= 0x97; self.B ^= 0x8
            self.C |= (0x50501010 - j)&0xFFFFFFFF
            self.D ^= (0x60606161 + j)&0xFFFFFFFF
            for i in range(64):
                which = i>>4
                if which == 0:
                    offset = 2*(i &3) - i + 44
                    t = self.calculate(self.f4, ((i*3+5)&15), offset)
                elif which == 1:
                    offset = 2*(i &3) - i +76
                    t = self.calculate(self.f5, ((i*7)&15), offset)
                elif which == 2:
                    offset = (i &15)
                    t = self.calculate(self.f2, (i &15), offset)
                else:
                    offset = (i -32)&0xFFFFFFFF
                    t = self.calculate(self.f3, ((i*5+1)&15), offset)
                g = ((i>>4)+2)&3
                self.A, self.D, self.C = self.D, self.C, self.B
                shift = rotationTable[g][(i &3)]
                self.B = mask32(self.B + rol(t, shift))
            self.incrementData()

class Tag6FF1Encoder(Tag595BEncoder):
    md5table = md5magic2
    counter1 = 23
    def makeEncode(self) -> None:
        for j in range(self.counter1):
            self.A |= 0xA08097; self.B ^= 0xA010908
            self.C |= (0x60606161 - j)&0xFFFFFFFF
            self.D ^= (0x50501010 + j)&0xFFFFFFFF
            for i in range(64):
                which = i>>4
                k = (i &15) - ((i &12)<<1) +12
                if which == 0: t = self.calculate(self.f2, (i &15), (i+32)&0xFFFFFFFF)
                elif which == 1: t = self.calculate(self.f3, ((i*5+1)&15), (i&15))
                elif which == 2: t = self.calculate(self.f4, ((i*3+5)&15), (k+16)&0xFFFFFFFF)
                else: t = self.calculate(self.f5, ((i*7)&15), (k+48)&0xFFFFFFFF)
                self.A, self.D, self.C = self.D, self.C, self.B
                shift = rotationTable[which][(i &3)]
                self.B = mask32(self.B + rol(t, shift))
            self.incrementData()
        for j in range(17):
            self.A |= 0x100097; self.B ^= 0xA0008
            self.C |= (0x50501010 - j)&0xFFFFFFFF
            self.D ^= (0x60606161 + j)&0xFFFFFFFF
            for i in range(64):
                which = i>>4
                k = (i &15) - ((i &12)<<1) +12
                if which == 0:
                    shiftval = ((i &15)*3 +5)&15
                    t = self.calculate(self.f4, shiftval, (k+16))
                elif which == 1:
                    shiftval = ((i &3)*7 + (i &12)+4)&15
                    t = self.calculate(self.f5, shiftval, ((i &15)+32)&0xFFFFFFFF)
                elif which == 2:
                    t = self.calculate(self.f2, (k &15), k)
                else:
                    shiftval = ((i &15)*5 +1)&15
                    t = self.calculate(self.f3, shiftval, ((i &15)+48)&0xFFFFFFFF)
                g = ((i>>4)+2)&3
                self.A, self.D, self.C = self.D, self.C, self.B
                shift = rotationTable[g][(i &3)]
                self.B = mask32(self.B + rol(t, shift))
            self.incrementData()

class Tag1F5AEncoder(Tag595BEncoder):
    md5table = md5magic2
    def makeEncode(self) -> None:
        for _ in range(5):
            for j in range(64):
                k = 12 + (j &3) - (j &12)
                which = j>>4
                if which == 0: t = self.calculate(self.f2, j &15, j)
                elif which == 1: t = self.calculate(self.f3, ((j*5+1)&15), j)
                elif which == 2: t = self.calculate(self.f4, ((j*3+5)&15), (k+0x20)&0xFFFFFFFF)
                else: t = self.calculate(self.f5, ((j*7)&15), (k+0x30)&0xFFFFFFFF)
                self.B, self.D, self.A = self.D, self.A, self.C
                shift = rotationTable[which][(j &3)]
                self.C = mask32(self.C + rol(t, shift))
            self.incrementData()
    def incrementData(self) -> None:
        self.encData[0] = mask32(self.encData[0] + self.B)
        self.encData[1] = mask32(self.encData[1] + self.C)
        self.encData[2] = mask32(self.encData[2] + self.A)
        self.encData[3] = mask32(self.encData[3] + self.D)
    def calculate(self, func, key1: int, key2: int) -> int:
        tmp = func(self.C, self.A, self.D)
        combined = (self.md5table[key2] + self.encBlock[key1]) &0xFFFFFFFF
        return (self.B + encF1(tmp, combined)) &0xFFFFFFFF

class TagBF97Encoder(Tag6FF1Encoder):
    counter1 = 31

class TagE7A8Encoder(Tag595BEncoder):
    md5table = md5magic2
    loopParams = [17,13,12,8]
    encodeParams = [
        0x50501010, 0xA010908, 0xA08097, 0x60606161,
        0x60606161, 0xA0008,  0x100097, 0x50501010
    ]
    def initialData(self) -> List[int]:
        return [0,0,0,0]
    def makeEncode(self) -> None:
        for p in range(self.loopParams[0]):  #17
            self.A |= self.encodeParams[0]; self.B ^= self.encodeParams[1]
            self.C |= (self.encodeParams[2]-p)&0xFFFFFFFF
            self.D ^= (self.encodeParams[3]+p)&0xFFFFFFFF
            for j in range(0, self.loopParams[2], 4):
                self.shortcut(self.f2, j, j+32, 0, [0,1,2,3])
            for j in range(0, self.loopParams[2], 4):
                self.shortcut(self.f3, j, j, 1, [1,-2,-1,0])
            for j in range(self.loopParams[3],3,-4):
                self.shortcut(self.f4, j, j+16, 2, [-3,-4,-1,2])
            for j in range(self.loopParams[3],3,-4):
                self.shortcut(self.f5, j, j+48, 3, [2,3,2,-3])
            self.incrementData()
        for p in range(self.loopParams[1]):  #13
            self.A |= self.encodeParams[4]; self.B ^= self.encodeParams[5]
            self.C |= (self.encodeParams[6]-p)&0xFFFFFFFF
            self.D ^= (self.encodeParams[7]+p)&0xFFFFFFFF
            for j in range(self.loopParams[3],3,-4):
                self.shortcut(self.f4, j, j+16, 2, [-3,-4,-1,2])
            for j in range(0,self.loopParams[2],4):
                self.shortcut(self.f5, j, j+32, 3, [2,3,2,-3])
            for j in range(self.loopParams[3],0,-4):
                self.shortcut(self.f2, j, j, 0, [0,1,2,3])
            for j in range(0,self.loopParams[2],4):
                self.shortcut(self.f3, j, j+48, 1, [1,-2,3,0])
            self.incrementData()
    def shortcut(self, fun, j, md5_index, rot_index, indexes):
        for i in range(4):
            t = self.calculate(fun, (j + indexes[i]) &7, md5_index + i)
            self.A, self.D, self.C = self.D, self.C, self.B
            shift = rotationTable[rot_index][i]
            self.B = (self.B + rol(t, shift)) &0xFFFFFFFF

class TagE7A8EncoderSecond(TagE7A8Encoder):
    def __init__(self, encBlock: List[int]):
        super().__init__(encBlock)
        overfillArr = [
            (0xa0008 ^ 0x6d2f93a5),
            (0xa08097 ^ 0x6d2f93a5),
            (0xa010908 ^ 0x6d2f93a5),
            (0x60606161 ^ 0x6d2f93a5)
        ]
        extended = md5magic2[:] + overfillArr
        self.md5table = extended
        self.loopParams = [17,13,12,16]

class DellTag:
    Tag595B = "595B"; TagD35B = "D35B"; Tag2A7B = "2A7B"; TagA95B = "A95B"
    Tag1D3B = "1D3B"; Tag1F66 = "1F66"; Tag6FF1 = "6FF1"; Tag1F5A = "1F5A"
    TagBF97 = "BF97"; TagE7A8 = "E7A8"

encoders: Dict[str,object] = {
    DellTag.Tag595B: Tag595BEncoder,
    DellTag.Tag2A7B: Tag595BEncoder,
    DellTag.TagA95B: Tag595BEncoder,
    DellTag.Tag1D3B: Tag1D3BEncoder,
    DellTag.TagD35B: TagD35BEncoder,
    DellTag.Tag1F66: Tag1F66Encoder,
    DellTag.Tag6FF1: Tag6FF1Encoder,
    DellTag.Tag1F5A: Tag1F5AEncoder,
    DellTag.TagBF97: TagBF97Encoder,
    DellTag.TagE7A8: TagE7A8Encoder,
}

scanCodes = (
    "\0\x1B1234567890-=\x08\x09"
    "qwertyuiop[]\x0D\xFF"
    "asdfghjkl;'`\xFF\\"
    "zxcvbnm,./"
)
encscans = [
    0x05,0x10,0x13,0x09,0x32,0x03,0x25,0x11,0x1F,0x17,0x06,0x15,
    0x30,0x19,0x26,0x22,0x0A,0x02,0x2C,0x2F,0x16,0x14,0x07,0x18,
    0x24,0x23,0x31,0x20,0x1E,0x08,0x2D,0x21,0x04,0x0B,0x12,0x2E
]
asciiPrintable = "012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0"
extraCharacters = {
    "2A7B": asciiPrintable,
    "1F5A": asciiPrintable,
    "1D3B": "0BfIUG1kuPvc8A9Nl5DLZYSno7Ka6HMgqsJWm65yCQR94b21OTp7VFX2z0jihE33d4xtrew0",
    "1F66": "0ewr3d4xtUG1ku0BfIp7VFb21OTSno7KDLZYqsJWa6HMgCQR94m65y9Nl5Pvc8AjihE3X2z0",
    "6FF1": "08rptBxfbGVMz38IiSoeb360MKcLf4QtBCbWVzmH5wmZUcRR5DZG2xNCEv1nFtzsZB2bw1X0",
    "BF97": "0Q2drGk99rkQFMxN[Z5y3DGr16h638myIL2rzz2pzcU7JWLJ1EGnqRN4seZPRM2aBXIjbkGZ"
}

class SuffixType:
    ServiceTag = 0

def blockEncode(encBlock: List[int], tag: str) -> List[int]:
    if tag not in encoders:
        raise ValueError(f"Unknown tag: {tag}")
    klass = encoders[tag]
    return klass.encode(encBlock)

def byteArrayToInt(arr: List[int]) -> List[int]:
    resultLength = len(arr)>>2
    out = []
    for i in range(resultLength+1):
        val=0
        if i*4 < len(arr): val |= arr[i*4]
        if i*4+1 < len(arr): val |= (arr[i*4+1]<<8)
        if i*4+2 < len(arr): val |= (arr[i*4+2]<<16)
        if i*4+3 < len(arr): val |= (arr[i*4+3]<<24)
        val&=0xFFFFFFFF; out.append(val)
    return out

def intArrayToByte(arr: List[int]) -> List[int]:
    out=[]
    for num in arr:
        out.append(num&0xFF)
        out.append((num>>8)&0xFF)
        out.append((num>>16)&0xFF)
        out.append((num>>24)&0xFF)
    return out

def calculateSuffix(serial: List[int], tag: str, type_: int) -> List[int]:
    suffix = [0]*8
    if type_ == SuffixType.ServiceTag:
        arr1 = [1,2,3,4]; arr2 = [4,3,2]
    suffix[0] = serial[arr1[3]]
    suffix[1] = (serial[arr1[3]]>>5) | (((serial[arr1[2]]>>5)|(serial[arr1[2]]<<3)) & 0xF1)
    suffix[2] = serial[arr1[2]]>>2
    suffix[3] = (serial[arr1[2]]>>7)|(serial[arr1[1]]<<1)
    suffix[4] = (serial[arr1[1]]>>4)|(serial[arr1[0]]<<4)
    suffix[5] = serial[1]>>1
    suffix[6] = (serial[1]>>6)|(serial[0]<<2)
    suffix[7] = serial[0]>>3
    for i in range(8): suffix[i] &= 0xFF
    table = extraCharacters.get(tag, None)
    codesTable = [ord(c) for c in table] if table is not None else encscans
    for i in range(8):
        r = 0xAA
        if suffix[i] &1: r ^= serial[arr2[0]]
        if suffix[i] &2: r ^= serial[arr2[1]]
        if suffix[i] &4: r ^= serial[arr2[2]]
        if suffix[i] &8: r ^= serial[1]
        if suffix[i] &16: r ^= serial[0]
        suffix[i] = codesTable[r % len(codesTable)]
    return suffix

def resultToString(arr: List[int], tag: str) -> str:
    r = arr[0] %9; result = ""
    table = extraCharacters.get(tag, None)
    for i in range(16):
        if table is not None:
            result += table[arr[i] % len(table)]
        else:
            if r <= i and len(result)<8:
                idx = arr[i] % len(encscans)
                scan_char_idx = encscans[idx]
                if scan_char_idx < len(scanCodes):
                    result += scanCodes[scan_char_idx]
    return result

def calculateE7A8(block: List[int], klass) -> str:
    table = "Q92G0drk9y63r5DG1hLqJGW1EnRk[QxrFMNZ328I6myLr4MsPNeZR2z72czpzUJBGXbaIjkZ"
    encoded_32 = klass.encode(block)
    res_bytes = intArrayToByte(encoded_32)
    digest = hashlib.sha256(bytes(res_bytes)).digest()
    out_str=""
    for i in range(16):
        idx=(digest[i+16]+digest[i])%len(table)
        out_str+=table[idx]
    return out_str

def keygenDell(serial: str, tag: str, type_: int) -> List[str]:
    fullSerial = (serial + DellTag.Tag595B) if tag == DellTag.TagA95B else (serial + tag)
    fullSerialArray = [ord(c) for c in fullSerial]
    if tag == DellTag.TagE7A8:
        encBlock = byteArrayToInt(fullSerialArray)
        for i in range(16):
            if i>= len(encBlock): encBlock.append(0)
        out_str1 = calculateE7A8(encBlock, TagE7A8Encoder)
        out_str2 = calculateE7A8(encBlock, TagE7A8EncoderSecond)
        results = []
        if out_str1: results.append(out_str1)
        if out_str2: results.append(out_str2)
        return results
    suffix = calculateSuffix(fullSerialArray, tag, type_)
    fullSerialArray += suffix
    cnt=23
    if len(fullSerialArray)<=cnt: fullSerialArray+=[0]*(cnt-len(fullSerialArray)+1)
    fullSerialArray[cnt]=0x80
    encBlock=byteArrayToInt(fullSerialArray)
    for i in range(16):
        if i>= len(encBlock): encBlock.append(0)
    encBlock[14]=(cnt<<3)
    decodedBytes=intArrayToByte(blockEncode(encBlock, tag))
    outputResult=resultToString(decodedBytes, tag)
    return [outputResult] if outputResult else []

def checkDellTag(tag: str) -> bool:
    tag=tag.upper()
    valid_tags = {
        DellTag.Tag595B, DellTag.TagD35B, DellTag.Tag2A7B, DellTag.TagA95B,
        DellTag.Tag1D3B, DellTag.Tag1F66, DellTag.Tag6FF1, DellTag.Tag1F5A,
        DellTag.TagBF97, DellTag.TagE7A8
    }
    return (tag in valid_tags)

def dellSolverFun(password: str) -> List[str]:
    if len(password)!=11: return []
    serial_part = password[:7].upper()
    tag_part = password[7:].upper()
    if not checkDellTag(tag_part): return []
    return keygenDell(serial_part, tag_part, SuffixType.ServiceTag)

def dellSolverValidator(password: str) -> bool:
    return (len(password)==11 and checkDellTag(password[7:]))

class DellPfsExtractorTab:
    SUPPORTED_EXT = (".exe", ".rcv")

    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)

        outer = tk.Frame(self.frame, padx=20, pady=20, bg="#F0F0F0")
        outer.pack(fill="both", expand=True)

        # Title
        tk.Label(
    outer,
    text="Powered by Dell PFS Update Extractor by Plato Mavropoulos",
    font=("Segoe UI", 9, "italic"),
    fg="gray25",
    bg="#F0F0F0"
   ).pack(pady=(0, 10))


        # *** REQUIRED INFO ***
        tk.Label(
            outer,
            text=(
                "This tool works ONLY with Dell BIOS .EXE and .RCV update files.\n"
                "Raw .BIN dumps are NOT supported."
            ),
            fg="darkred",
            font=("Segoe UI", 10, "bold"),
            justify="center",
            bg="#F0F0F0"
        ).pack(pady=(0, 15))

        # File selection row
        row1 = tk.Frame(outer, bg="#F0F0F0")
        row1.pack(fill="x", pady=5)

        tk.Label(row1, text="BIOS Update File:", bg="#F0F0F0").pack(side=tk.LEFT, padx=(0, 5))

        self.file_entry = tk.Entry(row1, width=50)
        self.file_entry.pack(side=tk.LEFT, fill="x", expand=True)

        tk.Button(row1, text="Browse", command=self.browse_file).pack(side=tk.LEFT, padx=5)

        # Output folder row
        row2 = tk.Frame(outer, bg="#F0F0F0")
        row2.pack(fill="x", pady=5)

        tk.Label(row2, text="Extract To:", bg="#F0F0F0").pack(side=tk.LEFT, padx=(0, 5))

        self.out_entry = tk.Entry(row2, width=50)
        self.out_entry.pack(side=tk.LEFT, fill="x", expand=True)

        tk.Button(row2, text="Select Folder", command=self.browse_output).pack(side=tk.LEFT, padx=5)

        # Extract button
        self.extract_btn = tk.Button(
            outer, text="Extract", width=18,
            command=self.do_extract,
            state="disabled"     # Disabled until valid file chosen
        )
        self.extract_btn.pack(pady=10)

        # Log window
        self.log_area = scrolledtext.ScrolledText(outer, height=12, width=80, state="disabled")
        self.log_area.pack(pady=10)

    # ---------------- Support funcs ----------------

    def log(self, msg):
        self.log_area.config(state="normal")
        self.log_area.insert(tk.END, msg + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state="disabled")

    def get_default_output_folder(self, input_path: str) -> str:
        base_dir = os.path.dirname(input_path)
        stem = os.path.splitext(os.path.basename(input_path))[0]
        out_dir = os.path.join(base_dir, stem + "_EXTRACTED")
        os.makedirs(out_dir, exist_ok=True)
        return out_dir


    def open_folder(self, folder: str):
        """Open folder in Explorer (Windows)."""
        try:
            if sys.platform.startswith("win"):
                os.startfile(folder)  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", folder])
        except Exception as e:
            self.log(f"[!] Failed to open folder: {e}")

    def browse_file(self):
        path = filedialog.askopenfilename(
            title="Select Dell BIOS Update File",
            filetypes=[("Dell BIOS files", "*.exe;*.rcv;*.RCV;*.EXE"), ("All files", "*.*")]
        )
        if not path:
            return

        path = path.strip()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, path)

        # Validate extension
        ext = os.path.splitext(path)[1].lower()

        if ext not in self.SUPPORTED_EXT:
            messagebox.showwarning(
                "Unsupported File",
                "This is NOT a Dell .EXE or .RCV BIOS update file.\n"
                "Raw .BIN dumps cannot be processed."
            )
            self.extract_btn.config(state="disabled")
            return

        # Valid file – enable extract
        self.extract_btn.config(state="normal")

        # Auto-populate default output folder next to the BIOS file
        default_out = self.get_default_output_folder(path)
        self.out_entry.delete(0, tk.END)
        self.out_entry.insert(0, default_out)

    def browse_output(self):
        folder = filedialog.askdirectory(title="Select Output Folder")
        if folder:
            self.out_entry.delete(0, tk.END)
            self.out_entry.insert(0, folder)

    def do_extract(self):
        if run_pfs_extract is None:
            messagebox.showerror(
                "PFS Extractor Missing",
                "The backend extractor is not available.\n"
                "Check vendor/dell_pfs_extract folder."
            )
            return

        input_path = self.file_entry.get().strip()
        output_dir = self.out_entry.get().strip()

        if not input_path or not os.path.exists(input_path):
            messagebox.showerror("Error", "Select a valid Dell BIOS .EXE or .RCV file.")
            return

        # If user didn’t set output dir for some reason, fall back to default
        if not output_dir:
            output_dir = self.get_default_output_folder(input_path)
            self.out_entry.delete(0, tk.END)
            self.out_entry.insert(0, output_dir)

        ext = os.path.splitext(input_path)[1].lower()
        if ext not in self.SUPPORTED_EXT:
            messagebox.showerror(
                "Unsupported File",
                "This tool only supports Dell BIOS .EXE or .RCV packages.\n"
                "Raw .BIN files cannot be extracted."
            )
            return

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        # Run extraction
        try:
            self.log("Starting extraction...")
            run_pfs_extract(input_path, output_dir)
            self.log("Extraction COMPLETE.")
            messagebox.showinfo("Success", "Extraction completed successfully.")

            # Auto-open the folder in Explorer
            self.open_folder(output_dir)

        except Exception as e:
            self.log(f"ERROR: {e}")
            messagebox.showerror("Extraction Failed", str(e))



class BiosUnlockerTab:
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)

        tk.Label(self.frame, text="Select BIOS File:", font=("Arial", 10, "bold")).pack(pady=5)
        file_frame = tk.Frame(self.frame); file_frame.pack(pady=5)
        self.entry = tk.Entry(file_frame, width=50, borderwidth=0, font=("Arial", 9)); self.entry.pack(side=tk.LEFT, padx=5)
        tk.Button(file_frame, text="Browse", command=self.browse_file, bg="#4682B4", fg="white").pack(side=tk.RIGHT, padx=5)

        self.patch_button = tk.Button(
            self.frame, text="Patch BIOS", command=self.patch_bios,
            bg="white", fg="black", font=("Arial", 10, "bold"),
            padx=10, state=tk.DISABLED, borderwidth=1, relief="solid",
            activebackground="#E0E0E0"
        )
        self.patch_button.pack(pady=10)

        log_frame = tk.Frame(self.frame, bg="#36454F"); log_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        tk.Label(log_frame, text="Patching Log:", bg="#36454F", fg="white", anchor="w").pack(fill=tk.X)

        self.log_text = scrolledtext.ScrolledText(
            log_frame, height=18, state=tk.DISABLED,
            bg="black", fg="#00FF00", font=("Consolas", 9)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        about_text = ""

        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, "Welcome to Dell-8FC8-BIOS-UNLOCKER\n")
        self.log_text.insert(tk.END, "This tool helps unlock Dell BIOS by patching specific patterns\n")
        self.log_text.insert(tk.END, "Please select a BIOS file to begin\n")
        self.log_text.insert(tk.END, "For password generation, use the Password Generator tab\n")
        self.log_text.configure(state=tk.DISABLED)

    def browse_file(self):
        path = filedialog.askopenfilename(
            title="Select BIOS binary",
            filetypes=(("BIOS images", "*.bin *.rom *.fd *.efi"), ("All files", "*.*")),
        )
        if path:
            self.entry.delete(0, tk.END)
            self.entry.insert(0, path)
            self.patch_button.config(state=tk.NORMAL)

    def log_message(self, message: str):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def clear_log(self):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def patch_bios(self):
        file_path = self.entry.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid BIOS file first!")
            return

        self.log_message("Starting BIOS patching process...")

        try:
            with open(file_path, "rb") as f:
                bios_data = bytearray(f.read())

            file_name = os.path.basename(file_path)
            file_size = len(bios_data)
            self.log_message(f"Loaded BIOS file: {file_name} (Size: {file_size} bytes)")

            # Intel signature check (same as old working unlocker)
            intel_signature = convert_hex_to_bytes("5AA5F00F03")
            self.log_message("Searching for Intel signature...")
            intel_offset = find_intel_signature(bios_data, intel_signature)
            if intel_offset >= 0:
                self.log_message(f"Intel signature found at offset 0x{intel_offset:X}")
            else:
                self.log_message("Intel signature not found")
                messagebox.showerror(
                    "Error",
                    "Intel signature not found. This may not be a valid BIOS file."
                )
                return

            # Pattern 1
            self.log_message("Checking for first pattern...")
            first_pattern = r"^00FCAA[0-9A-F]{2,4}000000[0-9A-F]{2,}.*$"
            first_replace_bytes = convert_hex_to_bytes("00FC00")
            first_offsets = find_pattern_matches(bios_data, first_pattern)
            for offset in first_offsets:
                self.log_message(f"Pattern found at offset 0x{offset:X} and replaced.")
                bios_data[offset:offset+6] = first_replace_bytes + bytes(
                    [0] * (6 - len(first_replace_bytes))
                )

            # Pattern 2
            self.log_message("Almost done! Checking second pattern...")
            second_pattern = r"^00FDAA[0-9A-F]{2,4}000000[0-9A-F]{2,}.*$"
            second_replace_bytes = convert_hex_to_bytes("00FD00")
            second_offsets = find_pattern_matches(bios_data, second_pattern)
            for offset in second_offsets:
                self.log_message(f"Pattern found at offset 0x{offset:X} and replaced.")
                bios_data[offset:offset+6] = second_replace_bytes + bytes(
                    [0] * (6 - len(second_replace_bytes))
                )

            if first_offsets or second_offsets:
                patched_file_path = os.path.join(
                    os.path.dirname(file_path), f"patched_{file_name}"
                )
                with open(patched_file_path, "wb") as f:
                    f.write(bios_data)

                self.log_message(f"Patched and saved as patched_{file_name}")
                self.patch_button.config(text="Completed!", state=tk.DISABLED)

                messagebox.showinfo(
                    "Success", f"BIOS patched successfully!\nSaved as {patched_file_path}"
                )

                self.log_message(
                    "Use your BIOS Programmer to flash the patched bin file to your device."
                )
                self.log_message(
                    "Reboot the device.. A warning will come up: "
                    "'The Service Tag has not been programmed...'."
                )
                self.log_message(
                    "After inputting the Service Tag, the device will reboot again and you "
                    "should be able to boot to the Windows OS."
                )
                self.log_message(
                    "For other BIOS password needs, use the Password Generator tab."
                )
            else:
                self.log_message("Patching failed: No patterns found")
                messagebox.showwarning(
                    "Warning", "No matching patterns found. Patch unsuccessful."
                )

        except Exception as e:
            self.log_message(f"Error during patching: {e}")
            messagebox.showerror("Error", f"An error occurred: {e}")
class PasswordGeneratorTab:
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)

        outer = tk.Frame(self.frame, padx=20, pady=20, bg="#F0F0F0")
        outer.pack(fill="both", expand=True)

        # --- Title ---
        title = tk.Label(
            outer,
            text="Dell BIOS Password Generator",
            font=("Segoe UI", 14, "bold"),
            bg="#F0F0F0"
        )
        title.pack(pady=(0, 10))

        # --- Subtitle / instructions line ---
        subtitle = tk.Label(
            outer,
            text=(
                "Enter 7-character Service Tag followed by 4-character Tag suffix\n"
                "(Example: 1A2B3C4595B)"
            ),
            font=("Segoe UI", 9),
            bg="#F0F0F0",
            justify=tk.CENTER
        )
        subtitle.pack(pady=(0, 15))

        # --- Input row: Service Tag + Suffix ---
        input_row = tk.Frame(outer, bg="#F0F0F0")
        input_row.pack(pady=(0, 8))

        tk.Label(
            input_row,
            text="Service Tag + Suffix:",
            font=("Segoe UI", 9),
            bg="#F0F0F0"
        ).pack(side=tk.LEFT, padx=(0, 5))

        self.tag_entry = tk.Entry(input_row, width=22, font=("Consolas", 10))
        self.tag_entry.pack(side=tk.LEFT)
        self.tag_entry.bind("<Return>", lambda e: self.compute_password())

        # --- Common tags row (clickable) ---
        common_row = tk.Frame(outer, bg="#F0F0F0")
        common_row.pack(pady=(2, 10))

        tk.Label(
            common_row,
            text="Common Tags:",
            font=("Segoe UI", 9),
            bg="#F0F0F0"
        ).pack(side=tk.LEFT)

        self.common_tags = ["595B", "D35B", "2A7B", "1D3B", "1F66", "6FF1", "1F5A", "BF97", "E7A8"]
        for tag in self.common_tags:
            lbl = tk.Label(
                common_row,
                text="  " + tag,
                font=("Segoe UI", 9, "underline"),
                fg="blue",
                cursor="hand2",
                bg="#F0F0F0"
            )
            lbl.pack(side=tk.LEFT)
            lbl.bind("<Button-1>", lambda e, t=tag: self.insert_suffix(t))

        # --- Compute button (centered) ---
        btn_frame = tk.Frame(outer, bg="#F0F0F0")
        btn_frame.pack(pady=(0, 12))

        self.compute_btn = tk.Button(
            btn_frame,
            text="Compute Password",
            width=18,
            command=self.compute_password
        )
        self.compute_btn.pack()

        # --- Password output row ---
        output_row = tk.Frame(outer, bg="#F0F0F0")
        output_row.pack(fill="x", pady=(0, 6))

        tk.Label(
            output_row,
            text="Password:",
            font=("Segoe UI", 9),
            bg="#F0F0F0"
        ).pack(side=tk.LEFT)

        self.password_entry = tk.Entry(output_row, font=("Consolas", 10))
        self.password_entry.pack(side=tk.LEFT, fill="x", expand=True, padx=(5, 0))
        self.password_entry.config(state="readonly")

        # --- Red note about 8FC8 ---
        note = tk.Label(
            outer,
            text="Note: For 8FC8 suffixes, use the 'BIOS Unlocker' tool instead.",
            font=("Segoe UI", 9),
            fg="red",
            bg="#F0F0F0"
        )
        note.pack(pady=(4, 10))

        # --- Detailed instructions block ---
        instructions_text = (
            "Instructions:\n"
            "1. Enter your 7-character Dell Service Tag followed by a 4-character tag suffix\n"
            "2. Click 'Compute Password' to generate the BIOS master password\n"
            "3. For E7A8 tags, you may receive two possible passwords – try both\n\n"
            "Warning: Use at your own risk. Incorrect BIOS passwords can lock your system."
        )
        instructions = tk.Label(
            outer,
            text=instructions_text,
            font=("Segoe UI", 9),
            justify=tk.LEFT,
            bg="#F0F0F0"
        )
        instructions.pack(anchor="w")

    # --- Helper: clicking a common tag fills/updates suffix ---
    def insert_suffix(self, suffix: str):
        current = self.tag_entry.get().strip().upper()
        # keep first 7 as service tag, then append suffix
        if len(current) >= 7:
            base = current[:7]
        else:
            base = current  # user can still finish typing
        new_value = (base + suffix)[:11]
        self.tag_entry.delete(0, tk.END)
        self.tag_entry.insert(0, new_value)
        self.tag_entry.icursor(tk.END)

    # --- Clear & write to password field ---
    def _set_password_field(self, text: str):
        self.password_entry.config(state="normal")
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, text)
        self.password_entry.config(state="readonly")

    # --- Main compute logic (uses your existing keygen code) ---
    def compute_password(self):
        raw = self.tag_entry.get().strip().upper()
        self.tag_entry.delete(0, tk.END)
        self.tag_entry.insert(0, raw)

        if not dellSolverValidator(raw):
            self._set_password_field("Invalid input. Example: GW49GW28FC8")
            return

        try:
            results = dellSolverFun(raw)
        except Exception as e:
            self._set_password_field(f"Error: {e}")
            return

        if not results:
            self._set_password_field("No password generated for this tag.")
        else:
            # E7A8 can return 2 passwords; show them side by side
            self._set_password_field("  /  ".join(results))


class AssetManagerTab:
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)

        outer = tk.Frame(self.frame, padx=40, pady=40, bg="#F0F0F0")
        outer.pack(fill="both", expand=True)

        # --- Title (matches old look) ---
        title = tk.Label(
            outer,
            text="Asset Tag Manager",
            font=("Segoe UI", 14, "bold"),
            bg="#F0F0F0"
        )
        title.pack(pady=(0, 20))

        # --- Form layout (labels + entries) ---
        form = tk.Frame(outer, bg="#F0F0F0")
        form.pack()

        # Current Asset Tag
        tk.Label(
            form,
            text="Current Asset Tag:",
            font=("Segoe UI", 10),
            anchor="e",
            width=20,
            bg="#F0F0F0"
        ).grid(row=0, column=0, padx=(0, 8), pady=3, sticky="e")

        self.current_entry = tk.Entry(form, width=30, font=("Consolas", 10))
        self.current_entry.grid(row=0, column=1, pady=3, sticky="w")
        self.current_entry.config(state="readonly")

        # New Asset Tag
        tk.Label(
            form,
            text="New Asset Tag:",
            font=("Segoe UI", 10),
            anchor="e",
            width=20,
            bg="#F0F0F0"
        ).grid(row=1, column=0, padx=(0, 8), pady=3, sticky="e")

        self.new_entry = tk.Entry(form, width=30, font=("Consolas", 10))
        self.new_entry.grid(row=1, column=1, pady=3, sticky="w")

        # Setup password (optional)
        tk.Label(
            form,
            text="Setup Password (optional):",
            font=("Segoe UI", 10),
            anchor="e",
            width=20,
            bg="#F0F0F0"
        ).grid(row=2, column=0, padx=(0, 8), pady=3, sticky="e")

        self.setup_entry = tk.Entry(form, width=30, show="*", font=("Consolas", 10))
        self.setup_entry.grid(row=2, column=1, pady=3, sticky="w")

        # --- Buttons row (Refresh / Update / Restart → BIOS) ---
        btn_row = tk.Frame(outer, bg="#F0F0F0")
        btn_row.pack(pady=(15, 0))

        self.refresh_btn = tk.Button(btn_row, text="Refresh", command=self.refresh_asset_tag_manual)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)

        self.update_btn = tk.Button(btn_row, text="Update Asset Tag", command=self.update_asset_tag)
        self.update_btn.pack(side=tk.LEFT, padx=5)

        self.reboot_btn = tk.Button(btn_row, text="Restart → BIOS", command=self.restart_to_bios)
        self.reboot_btn.pack(side=tk.LEFT, padx=5)

        # --- Auto-load current asset tag on startup (no button press needed) ---
        self.frame.after(200, self.refresh_asset_tag_auto)

    # ---------------- Internal helpers ----------------

    def _set_current_asset(self, value: str):
        """Update the read-only 'Current Asset Tag' field."""
        self.current_entry.config(state="normal")
        self.current_entry.delete(0, tk.END)
        self.current_entry.insert(0, value)
        self.current_entry.config(state="readonly")

    def _detect_asset_tag(self) -> str:
        """
        Try CIM/WMI first, then fall back to CCTK if needed.
        Returns the (possibly empty) asset string or raises on true failure.
        """
        # 1) CIM/WMI read path
        try:
            tag = get_asset_tag_cim_only()
            # get_asset_tag_cim_only returns "" when tag is blank or placeholder.
            log(f"AssetTag (CIM/WMI) read: '{tag}'")
            return tag
        except Exception as e:
            log(f"AssetTag CIM/WMI read failed, will try CCTK: {e}")

        # 2) CCTK fallback
        exe, folder = find_cctk_bundle()
        ensure_hapi_present(folder)
        tag = get_asset_tag_cctk(exe)
        log(f"AssetTag (CCTK) read: '{tag}'")
        return tag

    # ---------------- UI actions ----------------

    def refresh_asset_tag_auto(self):
        """Called once when the tab is created; silent on failure."""
        try:
            tag = self._detect_asset_tag()
            self._set_current_asset(tag)
        except Exception as e:
            log(f"Auto asset refresh failed: {e}")
            # Leave field blank; no popup during startup.

    def refresh_asset_tag_manual(self):
        """Called when user clicks the Refresh button; show errors."""
        try:
            tag = self._detect_asset_tag()
            self._set_current_asset(tag)
        except Exception as e:
            log(f"Manual asset refresh failed: {e}")
            messagebox.showerror("Asset Tag", f"Failed to read Asset Tag.\n\n{e}")

    def update_asset_tag(self):
        new_tag = self.new_entry.get().strip()
        setup_pwd = self.setup_entry.get().strip() or None

        # Allow blank to clear, but confirm first
        if new_tag == "":
            if not messagebox.askyesno(
                "Clear Asset Tag",
                "New Asset Tag is blank.\n\nThis will CLEAR the Asset Tag.\n\nContinue?"
            ):
                return

        try:
            exe, folder = find_cctk_bundle()
        except Exception as e:
            log(f"CCTK not found: {e}")
            messagebox.showerror(
                "Asset Tag",
                "Unable to locate cctk.exe bundle.\n\n"
                f"{e}\n\nPlace CCTK under vendor\\cctk\\x86_64 or set DELL_CCTK_DIR."
            )
            return

        try:
            ensure_hapi_present(folder)
            set_asset_tag(exe, new_tag, setup_pwd)
            log(f"AssetTag updated to '{new_tag}'")
            messagebox.showinfo("Asset Tag", "Asset Tag updated successfully.")
            # Refresh display
            self.refresh_asset_tag_manual()
        except Exception as e:
            log(f"AssetTag update failed: {e}")
            messagebox.showerror("Asset Tag", f"Failed to update Asset Tag.\n\n{e}")

    def restart_to_bios(self):
        if not messagebox.askyesno(
            "Restart to BIOS",
            "This will immediately restart the system and enter BIOS setup.\n\nContinue?"
        ):
            return
        try:
            log("User requested Restart → BIOS")
            fast_restart_to_bios()
        except Exception as e:
            log(f"Restart to BIOS failed: {e}")
            messagebox.showerror("Restart to BIOS", f"Failed to restart into BIOS.\n\n{e}")


#######################

class DellToolsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Dell BIOS Tools.V2.5")
        self.root.geometry("700x620")
        self.root.configure(bg="#36454F")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Tabs (correct order)
        self.unlocker_tab = BiosUnlockerTab(self.notebook)
        self.password_tab = PasswordGeneratorTab(self.notebook)
        self.asset_tab = AssetManagerTab(self.notebook)
        self.pfs_tab = DellPfsExtractorTab(self.notebook)

        self.notebook.add(self.unlocker_tab.frame, text="BIOS Unlocker")
        self.notebook.add(self.password_tab.frame, text="Password Generator")
        self.notebook.add(self.asset_tab.frame, text="Asset Manager")
        self.notebook.add(self.pfs_tab.frame, text="Dell PFS Extractor")


class FadeLogo:
    def __init__(self, parent, image_path, size=48, step=3, interval=80):
        self.parent = parent
        self.alpha = 255
        self.direction = -1
        self.step = step
        self.interval = interval

        self.canvas = tk.Canvas(parent, width=size, height=size, highlightthickness=0, bd=0)
        self.canvas.pack(side="bottom", pady=6)

        if Image is not None and ImageTk is not None:
            img = Image.open(image_path).convert("RGBA")
            img = img.resize((size, size), Image.LANCZOS)
            self.base = img
            self.tk_img = ImageTk.PhotoImage(self.base)
            self.can_fade = True
        else:
            # Fallback: Tkinter native PNG loader (no PIL)
            img = tk.PhotoImage(file=image_path)

            # Resize using subsample to approximate requested size
            w, h = img.width(), img.height()
            if w > size:
                factor = max(1, int(w / size))
                img = img.subsample(factor, factor)

            self.tk_img = img
            self.can_fade = False
        self.img_id = self.canvas.create_image(size // 2, size // 2, image=self.tk_img)

        # start fade automatically
        self._animate()

    def _animate(self):
        try:
            frame = self.base.copy()
            frame.putalpha(self.alpha)
            self.tk_img = ImageTk.PhotoImage(frame)
            self.canvas.itemconfigure(self.img_id, image=self.tk_img)

            self.alpha += self.direction * self.step
            if self.alpha <= 90 or self.alpha >= 255:
                self.direction *= -1
        except Exception:
            return

        if getattr(self, 'can_fade', False):
            self.parent.after(self.interval, self._animate)

def main():
    ensure_admin_windows()
    root = tk.Tk()
    app = DellToolsApp(root)

    # -------------------------------------------------
    # Bottom banner (logo only, no text)
    # -------------------------------------------------
    banner = tk.Frame(root, bg="#36454F")
    banner.pack(side="bottom", fill="x")

    info_text = ""

    tk.Label(
        banner,
        text=info_text,
        fg="#D0D0D0",
        bg="#36454F",
        justify="center",
        font=("Segoe UI", 9)
    ).pack(pady=(8, 4))

    app.logo = FadeLogo(
        banner,
        resource_path(os.path.join("icon", "DellBiosTools.png")),
        size=48
    )

    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        pass
    except Exception as e:
        import traceback
        with open("error_log.txt", "w", encoding="utf-8") as f:
            f.write("UNHANDLED EXCEPTION IN GUI:\n")
            f.write(traceback.format_exc())
        try:
            tmp = tk.Tk(); tmp.withdraw()
            messagebox.showerror(
                "Fatal Error",
                "A critical error occurred. Details saved to error_log.txt"
            )
            tmp.destroy()
        except Exception:
            pass