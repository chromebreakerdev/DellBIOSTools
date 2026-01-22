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

1. Download **DellBiosTools_v2.5.zip**
2. Extract the ZIP
3. Double-click:


> **Note:** On first run, Windows SmartScreen may display a warning because the executable is unsigned.
> Click **More info** → **Run anyway** to proceed.

No Python installation is required. ✅

### 🔐 SHA-256 Verification (ZIP)

2f87dbabc6295f55b8e75109b46149db8f57584d463c77c179d963f2a3daf614

Prebuilt EXE releases may include additional UI enhancements not present in the raw Python source.
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

### 1. Dell BIOS Unlocker (8FC8 Patcher)
- Unlocks Dell BIOS by patching specific 8FC8 suffix patterns
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
## IN-CIRCUIT FLASHING NOTES

In-circuit flashing using a pogo-pin adapter (such as with a T48 programmer) may be attempted.
If a stable read cannot be achieved, removal of the SPI chip may be required.

------------------------------------------------------------
## ⚠️ Disclaimer

This tool is provided as-is with no warranty.
Always back up your BIOS before patching.
Use at your own risk.

------------------------------------------------------------
## 📜 License

MIT — free to use, share, and modify

------------------------------------------------------------
## Credits

- Original BIOS Unlocker tool by Rex98 & Techshack Cebu
- Research by Dogbert and Asyncritus
- Dell PFS Update Extractor by Plato Mavropoulos
- Tooling and integration by **chromebreakerdev**

------------------------------------------------------------
## ☕ Support My Work

https://www.buymeacoffee.com/chromebreakerdev
