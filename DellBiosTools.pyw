import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import re
import os
import sys
import binascii
import subprocess
import hashlib
import ctypes
import shlex
from collections import defaultdict
from typing import List, Dict, Optional
from datetime import datetime

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
    # Root-of-drive vendor drop (supports \vendor\cctk\x86_64)
    maybe_root = os.path.abspath(r"\vendor\cctk\x86_64\cctk.exe")
    maybe_root_alt = os.path.abspath(r"\vendor\cctk\X86_64\cctk.exe")
    # Env override
    env_dir = os.environ.get("DELL_CCTK_DIR", "")
    env_exe = os.path.join(env_dir, "cctk.exe") if env_dir else ""
    return [
        maybe_root, maybe_root_alt, env_exe,
        os.path.join(BASE_DIR, "vendor", "cctk", "x86_64", "cctk.exe"),
        os.path.join(BASE_DIR, "vendor", "cctk", "X86_64", "cctk.exe"),
        os.path.join(BASE_DIR, "cctk", "x86_64", "cctk.exe"),
        os.path.join(BASE_DIR, "cctk.exe"),
        r"X:\Windows\System32\cctk\X86_64\cctk.exe",
        r"C:\Program Files (x86)\Dell\Command Configure\X86_64\cctk.exe",
        r"C:\Program Files\Dell\Command Configure\X86_64\cctk.exe",
    ]

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

################################################################################
# PART 3: GUI TABS (existing + new Asset Manager)
################################################################################

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

        about_text = """ English Version of the Rex98-8FC8-Patcher
Based on the original tool by Rex98 & Techshack Cebu
Use with caution: Improper BIOS modification can damage your system."""
        tk.Label(self.frame, text=about_text, fg="#CCCCCC", font=("Arial", 8), justify=tk.LEFT).pack(pady=5)

        self.log_message("Welcome to Dell-8FC8-BIOS-UNLOCKER")
        self.log_message("This tool helps unlock Dell BIOS by patching specific patterns")
        self.log_message("Please select a BIOS file to begin")
        self.log_message("For password generation, use the Password Generator tab")

    def log_message(self, msg):
        self.log_text.config(state=tk.NORMAL); self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END); self.log_text.config(state=tk.DISABLED); self.parent.update()

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("BIOS Files", "*.bin *.rom *.fd *.bio"),("All Files", "*.*")]
        )
        if file_path:
            self.entry.delete(0, tk.END); self.entry.insert(0, file_path)
            self.log_message(f"Selected file: {file_path}")
            self.patch_button.config(text="Patch BIOS", state=tk.NORMAL)

    def patch_bios(self):
        file_path = self.entry.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid BIOS file first!")
            return
        self.log_message("Starting BIOS patching process...")
        try:
            with open(file_path, "rb") as f:
                bios_data = bytearray(f.read())
            file_name = os.path.basename(file_path); file_size = len(bios_data)
            self.log_message(f"Loaded BIOS file: {file_name} (Size: {file_size} bytes)")

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

            self.log_message("Checking for first pattern...")
            first_pattern = r"^00FCAA[0-9A-F]{2,4}000000[0-9A-F]{2,}.*$"
            first_replace_bytes = convert_hex_to_bytes("00FC00")
            first_offsets = find_pattern_matches(bios_data, first_pattern)
            for offset in first_offsets:
                self.log_message(f"Pattern found at offset 0x{offset:X} and replaced.")
                bios_data[offset:offset+6] = first_replace_bytes + bytes(
                    [0] * (6 - len(first_replace_bytes))
                )

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
        frame = tk.Frame(self.frame, padx=10, pady=10); frame.pack(expand=True)

        tk.Label(frame, text="Dell BIOS Password Generator", font=("Arial", 12, "bold")).pack(pady=10)
        tk.Label(
            frame,
            text="Enter 7-character Service Tag followed by 4-character Tag suffix\n"
                 "(Example: 1A2B3C4595B)",
            justify=tk.CENTER
        ).pack(pady=5)

        input_frame = tk.Frame(frame); input_frame.pack(pady=10)
        tk.Label(input_frame, text="Service Tag + Suffix:").pack(side=tk.LEFT)
        self.user_input = tk.Entry(input_frame, width=20); self.user_input.pack(side=tk.LEFT, padx=5)

        tags_frame = tk.Frame(frame); tags_frame.pack(pady=5)
        tk.Label(tags_frame, text="Common Tags:").pack(side=tk.LEFT)
        tk.Label(
            tags_frame,
            text="595B, D35B, 2A7B, 1D3B, 1F66, 6FF1, 1F5A, BF97, E7A8",
            fg="blue"
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            frame, text="Compute Password", command=self.compute_password,
            bg="#4682B4", fg="white"
        ).pack(pady=10)

        result_frame = tk.Frame(frame); result_frame.pack(pady=10, fill=tk.X)
        tk.Label(result_frame, text="Password:").pack(side=tk.LEFT)
        self.result_display = tk.Entry(result_frame, width=30, state="readonly")
        self.result_display.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        note_text = "Note: For 8FC8 suffixes, use the 'BIOS Unlocker' tool instead."
        tk.Label(frame, text=note_text, fg="red", font=("Arial", 9)).pack(pady=5)

        info_frame = tk.Frame(frame); info_frame.pack(pady=10, fill=tk.BOTH, expand=True)
        info_text = """Instructions:
1. Enter your 7-character Dell Service Tag followed by a 4-character tag suffix
2. Click "Compute Password" to generate the BIOS master password
3. For E7A8 tags, you may receive two possible passwords - try both

Warning: Use at your own risk. Incorrect BIOS passwords can lock your system."""
        tk.Label(info_frame, text=info_text, justify=tk.LEFT, font=("Arial", 9)).pack(anchor=tk.W)

    def compute_password(self):
        text = self.user_input.get().strip()
        self.result_display.config(state=tk.NORMAL); self.result_display.delete(0, tk.END)
        if dellSolverValidator(text):
            results = dellSolverFun(text)
            self.result_display.insert(
                0, ", ".join(results) if results else "No valid password found for this input."
            )
        else:
            self.result_display.insert(
                0, "Invalid input format. Use 7-char tag + 4-char suffix."
            )
        self.result_display.config(state="readonly")

class ServiceTagExtractorTab:
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)

        tk.Label(self.frame, text="Select BIOS File (.bin):", font=("Arial", 10, "bold")).pack(pady=5)
        file_frame = tk.Frame(self.frame); file_frame.pack(pady=5)
        self.entry = tk.Entry(file_frame, width=50, borderwidth=0, font=("Arial", 9))
        self.entry.pack(side=tk.LEFT, padx=5)
        tk.Button(file_frame, text="Browse", command=self.browse_file, bg="#4682B4", fg="white")\
            .pack(side=tk.RIGHT, padx=5)

        self.scan_button = tk.Button(
            self.frame, text="Extract Tags", command=self.extract_tags,
            bg="white", fg="black", font=("Arial", 10, "bold"),
            padx=10, state=tk.DISABLED, borderwidth=1, relief="solid"
        )
        self.scan_button.pack(pady=10)

        log_frame = tk.Frame(self.frame, bg="#36454F"); log_frame.pack(
            pady=5, padx=10, fill=tk.BOTH, expand=True
        )
        tk.Label(log_frame, text="Extractor Log:", bg="#36454F", fg="white", anchor="w")\
            .pack(fill=tk.X)
        self.log_text = scrolledtext.ScrolledText(
            log_frame, height=18, state=tk.DISABLED,
            bg="black", fg="#00FF00", font=("Consolas", 9)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self.log_message("Ready to extract Service Tags from BIOS dump")

    def log_message(self, msg):
        self.log_text.config(state=tk.NORMAL); self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END); self.log_text.config(state=tk.DISABLED); self.parent.update()

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("BIOS Files", "*.bin *.rom *.fd *.bio"),("All Files", "*.*")]
        )
        if file_path:
            self.entry.delete(0, tk.END); self.entry.insert(0, file_path)
            self.log_message(f"Selected file: {file_path}")
            self.scan_button.config(text="Extract Tags", state=tk.NORMAL)

    def extract_tags(self):
        file_path = self.entry.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid BIOS file!")
            return
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            tags = defaultdict(list)
            for i in range(len(data) - 16):
                chunk = data[i:i+14]; terminator = data[i+14:i+16]
                if self.is_ascii_upper_alnum_utf16le(chunk) and terminator == b'\x00\x00':
                    try:
                        tag = chunk.decode('utf-16le'); tags[tag].append(i)
                    except:
                        continue
            if not tags:
                self.log_message("❌ No valid tags found.")
                return
            self.log_message("=== Service Tag Occurrence Summary ===")
            sorted_tags = sorted(tags.items(), key=lambda x: -len(x[1]))
            for tag, offsets in sorted_tags:
                self.log_message(
                    f"Tag: {tag} | Found: {len(offsets)} times | "
                    f"Example Offset: 0x{offsets[0]:08X}"
                )
            most_common = sorted_tags[0]
            self.log_message(f"\n✅ Most Likely Service Tag: {most_common[0]}")
            self.log_message(f"   Occurrences: {len(most_common[1])}")
            self.log_message(
                f"   Region Range: 0x{min(most_common[1]):08X} – 0x{max(most_common[1]):08X}"
            )
        except Exception as e:
            self.log_message(f"[ERROR] {e}")

    def is_ascii_upper_alnum_utf16le(self, data):
        if len(data) != 14:
            return False
        for i in range(0, 14, 2):
            char = data[i]
            if not (48 <= char <= 57 or 65 <= char <= 90):
                return False
            if data[i+1] != 0x00:
                return False
        return True

class AssetManagerTab:
    """Hybrid UI: READ via CIM/WMI (Win11-safe), fallback to CCTK; WRITE via CCTK."""
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)

        wrap = tk.Frame(self.frame, padx=12, pady=12)
        wrap.pack(fill=tk.BOTH, expand=True)

        tk.Label(wrap, text="Asset Tag Manager", font=("Arial", 12, "bold")).pack(pady=(0,10))

        # Current tag
        cur_row = tk.Frame(wrap); cur_row.pack(fill=tk.X, pady=(0,6))
        tk.Label(cur_row, text="Current Asset Tag:", width=22, anchor="w").pack(side=tk.LEFT)
        self.current_var = tk.StringVar(value="(unknown)")
        tk.Entry(cur_row, textvariable=self.current_var, state="readonly", width=32)\
            .pack(side=tk.LEFT, padx=6)

        # New tag
        new_row = tk.Frame(wrap); new_row.pack(fill=tk.X, pady=(0,6))
        tk.Label(new_row, text="New Asset Tag:", width=22, anchor="w").pack(side=tk.LEFT)
        self.new_entry = tk.Entry(new_row, width=32); self.new_entry.pack(side=tk.LEFT, padx=6)

        # Optional setup password
        pwd_row = tk.Frame(wrap); pwd_row.pack(fill=tk.X, pady=(0,6))
        tk.Label(pwd_row, text="Setup Password (optional):", width=22, anchor="w")\
            .pack(side=tk.LEFT)
        self.pwd_entry = tk.Entry(pwd_row, width=32, show="*"); self.pwd_entry.pack(side=tk.LEFT, padx=6)

        # Buttons
        btns = tk.Frame(wrap); btns.pack(pady=10)
        tk.Button(btns, text="Refresh", command=self.refresh_asset).pack(side=tk.LEFT, padx=5)
        tk.Button(btns, text="Update Asset Tag", command=self.update_asset).pack(side=tk.LEFT, padx=5)
        tk.Button(btns, text="Restart → BIOS", command=self.reboot_bios).pack(side=tk.LEFT, padx=5)

        # Internal: keep path if we detect it once (not shown in UI)
        self.cctk_path: Optional[str] = None

        # Auto-refresh once
        try:
            self.refresh_asset()
        except Exception:
            pass

    def _ensure_cctk(self):
        if self.cctk_path and os.path.exists(self.cctk_path):
            return
        cctk_path, folder = find_cctk_bundle()
        self.cctk_path = cctk_path
        ensure_hapi_present(folder)

    def refresh_asset(self):
        """
        Read via CIM/WMI first (Win11-safe), then fall back to CCTK if CIM fails.
        """
        try:
            tag = get_asset_tag_cim_only()
            self.current_var.set(tag if tag else "(empty)")
            log(f"WMI/CIM AssetTag read OK: {tag}")
            return
        except Exception as e:
            log(f"WMI/CIM AssetTag read failed: {e}")
            cim_err = e

        # CCTK fallback read
        try:
            self._ensure_cctk()
            tag2 = get_asset_tag_cctk(self.cctk_path)
            self.current_var.set(tag2 if tag2 else "(empty)")
            log(f"CCTK AssetTag read OK: {tag2}")
        except Exception as e2:
            messagebox.showerror(
                "Read failed",
                f"Could not read Asset Tag.\n\nCIM/WMI error:\n{cim_err}\n\n"
                f"CCTK fallback error:\n{e2}"
            )

    def update_asset(self):
        """
        Set via CCTK. Auto-detect CCTK when needed.

        If New Asset Tag is left blank, we treat that as a request to CLEAR
        the Asset Tag (set it to empty), after a confirmation dialog.
        """
        new_tag_raw = self.new_entry.get()
        new_tag = (new_tag_raw or "").strip()
        setup_pwd = self.pwd_entry.get().strip() or None

        # If the user left it empty, ask if they want to clear it.
        if new_tag == "":
            if not messagebox.askyesno(
                "Clear Asset Tag",
                "New Asset Tag is blank.\n\n"
                "This will attempt to CLEAR the Asset Tag in BIOS "
                "(set it to empty).\n\n"
                "Do you want to continue?"
            ):
                return

        try:
            self._ensure_cctk()
        except Exception as e:
            messagebox.showerror(
                "CCTK required",
                "To set the Asset Tag you need Dell Command | Configure (cctk.exe + BIOSIntf.dll).\n\n"
                f"{e}"
            )
            return

        try:
            # For blank, this passes --asset= which on many Dell systems clears the tag.
            set_asset_tag(self.cctk_path, new_tag, setup_pwd)

            if new_tag:
                self.current_var.set(new_tag)
                log(f"Updated Asset Tag → {new_tag}")
                messagebox.showinfo("Success", f"Asset Tag updated to: {new_tag}")
            else:
                self.current_var.set("(empty)")
                log("Cleared Asset Tag (set to empty)")
                messagebox.showinfo("Success", "Asset Tag cleared (set to empty).")
        except Exception as e:
            messagebox.showerror("CCTK Error", str(e))

    def reboot_bios(self):
        if messagebox.askyesno(
            "Restart to BIOS", "Restart now to BIOS setup to verify the tag?"
        ):
            fast_restart_to_bios()

################################################################################
# PART 4: App Frame
################################################################################

class DellToolsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Dell BIOS Tools.V2.5")
        self.root.geometry("700x620")
        self.root.configure(bg="#36454F")

        self.notebook = ttk.Notebook(root); self.notebook.pack(
            fill=tk.BOTH, expand=True, padx=5, pady=5
        )
        self.unlocker_tab = BiosUnlockerTab(self.notebook)
        self.password_tab = PasswordGeneratorTab(self.notebook)
        self.service_tag_tab = ServiceTagExtractorTab(self.notebook)
        self.asset_tab = AssetManagerTab(self.notebook)

        self.notebook.add(self.unlocker_tab.frame, text="BIOS Unlocker")
        self.notebook.add(self.password_tab.frame, text="Password Generator")
        self.notebook.add(self.service_tag_tab.frame, text="Service Tag Extractor")
        self.notebook.add(self.asset_tab.frame, text="Asset Manager")

def main():
    ensure_admin_windows()
    root = tk.Tk()
    app = DellToolsApp(root)
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
