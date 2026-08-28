# DellBIOSTools V2.5

==================
## Requirements
------------
- **None for normal use** (prebuilt Windows EXE available)
- Windows 10/11 recommended

For advanced users building from source:
- Python 3.11 or greater is required to run the raw Python code (`DellBiosTools.pyw`)

==================
## 🚀 Quick Start (Recommended)

A **prebuilt standalone Windows EXE** is available via GitHub Releases.

### Download
👉 https://github.com/chromebreakerdev/DellBIOSTools/releases/latest

1. Download **DellBIOSTools_v2.5.1 zip**
2. Extract the ZIP
3. Double-click:


> **Note:** On first run, Windows SmartScreen may display a warning because the executable is unsigned.
> Click **More info** → **Run anyway** to proceed.

No Python installation is required. ✅

*prebuilt exe releases may include additional ui enhancements not present in the raw python source.*

------------------------------------------------------------
🔧 From Source (Developers / Advanced Users Only)

If you want to run DellBIOSTools directly from source (for development or research purposes):
Requirements:

Python 3.11 or newer

Windows 10/11

No build scripts are provided or supported.
Prebuilt EXE releases are published separately via GitHub Releases.

## 🛠 Usage

This tool combines several essential utilities for Dell BIOS management.
Tabs are ordered by most commonly used functions first.

### 1. Dell BIOS Unlocker 8FC8/CF1B
- Unlocks Dell BIOS by patching specific patterns
- Select a BIOS file, patch it, flash it, and reboot
- Requires an external programmer and a valid BIOS dump

### 2. Password Generator
- Generates Dell master passwords from Service Tags
- Supports multiple Dell suffix types (595B, D35B, 2A7B, 1D3B, 1F66, E7A8, etc.)

### 3. Asset Manager
- View, update, or clear Dell Asset Tag values
- Useful for IT inventory and post-repair validation
- Asset Tag reading depends on system firmware and SMBIOS support

### 4. Dell PFS BIOS Extractor
   - NOTE: OUTPUT FROM THIS FUNCTION IS NOT TO BE USED IN PLACE OF A VALID BIOS DUMP .BIN FILE FROM YOUR DEVICE.
   - ONLY USE THE ORIGINAL BIOS DUMP .BIN FILE WHICH YOU SHOULD HAVE PULLED FROM THE DEVICE. MAKE A COPY OF THIS BIN FILE FOR SAFE KEEPING
   - THEN USE THE COPY TO PATCH AND UPDATE THE DEVICE.
   - Extracts official Dell BIOS Update Packages (.EXE and .RCV)
   - Automatically creates an output folder next to the BIOS file:

         <same_directory>\<filename>_EXTRACTED\

   - Automatically opens the extracted folder in Windows Explorer
   - Requires no user selection of the output folder
   - Provides full logging of the extraction process

   Credit:
   This feature is powered by the Dell PFS Update Extractor by Plato Mavropoulos.
------------------------------------------------------------
## 🧪 DellBIOSTools V2.6 Beta

DellBIOSTools **V2.6 Beta** is an optional beta release that adds new BIOS dump verification, comparison, and analysis tools while retaining the existing DellBIOSTools features.

V2.5 remains available as the current stable release.

### What's New in V2.6 Beta

#### 🔍 BIOS Compare / Verify

A new **BIOS Compare / Verify** tab has been added for working with BIOS `.BIN` files.

### Compare Two Files

Compare an original BIOS dump against a modified or patched BIOS dump.

The comparison includes:

- SHA-256 hash of both files
- File size comparison
- Total number of changed bytes
- Percentage of unchanged data
- Changed byte regions
- First 200 differing bytes
- Ability to save a comparison report

The comparison function is read-only and does not modify either BIOS file.

---

### Verify Multiple Reads

Verify two or more BIOS reads taken from the same SPI flash chip.

The tool checks:

- File size
- SHA-256 hash
- Byte-for-byte consistency

A **PASS** is reported only when all selected BIOS reads are identical.

This can help verify that a programmer, clip, or pogo-pin connection is producing stable and repeatable BIOS reads before modifying or flashing the chip.

---

#### 🔬 BIOS Dump Analyzer

A new BIOS Dump Analyzer performs basic checks on a BIOS `.BIN` file.

The analyzer reports:

- File size
- SHA-256 hash
- `FF` byte distribution
- `00` byte distribution
- Longest `FF` run
- Longest `00` run
- Intel firmware signature detection
- Basic blank/erased dump warnings
- Selected flash-chip information
- Flash-chip capacity vs BIOS dump size

These checks are intended to help identify obviously incorrect, incomplete, blank, or mismatched BIOS dumps.

The analyzer does not guarantee that a BIOS image is valid or safe to flash.

---

#### 💾 Flash Chip Database

V2.6 Beta adds an expanded SPI flash-chip database for BIOS repair work.

Where information is available, the program can display:

- Chip manufacturer
- Chip model
- Capacity
- Voltage
- T48 programmer support
- Supported package
- ISP support

The database includes additional device information derived from the **XGecu T48 programmer device-support list**.

Package information relevant to Dell BIOS repair includes:

- SOIC8
- SOP8
- WSON8

If the exact capacity of a selected chip is not available in the database, the BIOS Dump Analyzer allows the capacity to be entered manually.

---

### Recommended V2.6 Beta Workflow

When reading a BIOS with an external programmer:

1. Identify and select the correct SPI flash chip.
2. Read the BIOS chip and save the first dump.
3. Read the chip again and save a second dump.
4. Use **Verify Multiple Reads** to confirm the dumps are identical.
5. Preserve an untouched copy of the verified original BIOS.
6. Make a separate working copy.
7. Patch or modify the working copy.
8. Use **Compare Two Files** to compare the modified BIOS against the original.
9. Review the reported changes before flashing.

> **Beta Notice:** The new V2.6 analysis and verification features are provided as additional diagnostic tools. Always preserve an untouched BIOS backup and independently verify firmware and flash-chip information before programming hardware.
### Download V2.6 Beta

👉 https://github.com/chromebreakerdev/DellBIOSTools/releases/tag/v2.6-beta

Download **DellBIOSTools_V2_6_Beta.exe** from the release assets.
------------------------------------------------------------
------------------------------------------------------------
## IN-CIRCUIT FLASHING NOTES

In-circuit flashing using a pogo-pin adapter (such as with a T48 programmer) may be attempted.
If a stable read cannot be achieved, removal of the SPI chip may be required.

------------------------------------------------------------
## ⚠️ Disclaimer

This project is provided for educational and research purposes only.

The software is distributed as-is, without warranty of any kind, express or implied.
The author assumes no responsibility or liability for any damage, data loss, hardware failure, or legal issues resulting from the use or misuse of this tool.

Always back up your BIOS before patching or flashing

Improper flashing can permanently damage hardware

Use this tool entirely at your own risk

You are responsible for ensuring you have proper authorization to modify any device or firmware

------------------------------------------------------------
## 📜 License

MIT — free to use, share, and modify

------------------------------------------------------------
## Credits

- Original BIOS Unlocker tool by Rex98 & Techshack Cebu
- Research by hpgl and Asyncritus
- Dell PFS Update Extractor by Plato Mavropoulos
- Python integration by **chromebreakerdev**

------------------------------------------------------------

