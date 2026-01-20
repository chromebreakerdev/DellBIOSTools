# DellBIOSTools V2.5

https://github.com/user-attachments/assets/73d3720e-0390-4011-ae4d-b0e051ed31b1

==================
## Requirements
------------
- Python 3.11 or greater is required to run the raw Python code (`DellBiosTools.pyw`)
- Windows 10/11 recommended for EXE build and usage

==================
## Preview

------------------------------------------------------------
## 🚀 Quick Build (Recommended)

To create a standalone EXE without worrying about Python setup:

1. Download this repo as ZIP and extract it.
2. Double-click:

    builddellbiostools.bat

3. The script will:
   - Check if Python is installed
   - If missing, install it automatically
   - Upgrade pip and install PyInstaller
   - Compile `DellBiosTools.pyw` into a standalone EXE
   - Embed the custom icon from the icon folder (if present)
   - Rename the EXE with a timestamp so Windows Explorer always shows the correct icon
   - Place the finished EXE in the project folder

When it finishes, you’ll see something like:

    DellBiosTools.exe

in the same folder. ✅

------------------------------------------------------------
## 🔧 Manual Build (Advanced)

1. Install Python 3.12+ from:
   https://www.python.org/downloads/windows/
   (Check “Add Python to PATH” during install)

2. Open Command Prompt in this repo folder.

3. Upgrade pip and install PyInstaller:

    pip install --upgrade pip
    pip install pyinstaller

4. Build the EXE:

    pyinstaller --noconfirm --onefile --windowed --icon icon\DellBiosTools.ico DellBiosTools.pyw

5. The EXE will appear at:

    dist\DellBiosTools.exe

6. (Optional) Clean up temporary build files:

    rmdir /s /q build
    rmdir /s /q dist
    del DellBiosTools.spec

------------------------------------------------------------
## 🛠 Usage

This tool combines several essential utilities for Dell BIOS management:

### 1. Dell BIOS Unlocker (8FC8 Patcher)
- Unlocks Dell BIOS by patching specific 8FC8 suffix patterns
- Select a BIOS file, patch it, flash it, and reboot

### 2. Password Generator
- Generates Dell master passwords from Service Tags
- Supports multiple Dell suffix types (595B, D35B, 2A7B, 1D3B, 1F66, E7A8, etc.)

### 3. Asset Manager (UPDATED in V2.5)
- View, update, or clear Dell Asset Tag values
- Useful for IT inventory and post-repair validation

### 4. Dell PFS BIOS Extractor (NEW in V2.5)
- Extracts official Dell BIOS update packages (.EXE / .RCV)
- Automatically creates an output folder next to the BIOS file
- Powered by Dell PFS Update Extractor by Plato Mavropoulos

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
- Python tooling by chromebreakerdev

------------------------------------------------------------
## ☕ Support My Work

https://www.buymeacoffee.com/chromebreakerdev
