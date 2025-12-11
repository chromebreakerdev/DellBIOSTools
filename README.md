# DellBIOSTools V2.5

https://github.com/user-attachments/assets/73d3720e-0390-4011-ae4d-b0e051ed31b1

==================
Requirements
------------
- Python 3.11 or greater is required to run the raw Python code (DellBiosTools.pyw)
- Windows 10/11 recommended for EXE build and usage

==================
Preview


------------------------------------------------------------
🚀 Quick Build (Recommended)

To create a standalone EXE without worrying about Python setup:

1. Download this repo as ZIP and extract it.
2. Double-click:

    builddellbiostools.bat

3. The script will:
   - Check if Python is installed
   - If missing, install it automatically
   - Upgrade pip and install PyInstaller
   - Compile DellBiosTools.pyw into a standalone EXE
   - Embed the custom icon from the icon folder (if present)
   - Rename the EXE with a timestamp so Windows Explorer always shows the correct icon
   - Place the finished EXE in the project folder

When it finishes, you’ll see something like:

    DellBiosTools.exe

in the same folder. ✅

------------------------------------------------------------
🔧 Manual Build (Advanced)

If you prefer to build manually:

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
🛠 Usage

This tool combines several essential utilities for Dell BIOS management:

1. Dell (8FC8 Patcher)
   - Unlocks Dell BIOS by patching specific 8FC8 suffix patterns
   - Steps:
     - Click "Browse" to select your BIOS file
     - Click "Patch BIOS" to apply the patch
     - Flash the patched BIOS and reboot
     - When prompted that "The Service Tag has not been programmed", enter your Service Tag
     - Reboot again, and the system should boot to Windows

2. Password Generator
   - Generates Dell master passwords from service tags
   - Supports multiple tag types (595B, D35B, 2A7B, 1D3B, 1F66, E7A8, etc.)
   - Steps:
     - Enter your 7-character Service Tag plus the 4-character suffix
     - Click "Compute Password"
     - Use the generated password to unlock your Dell system

3. Service Tag Extractor
   - Extracts Service Tag values from .bin BIOS files
   - Steps:
     - Load your Dell .bin file
     - Click "Extract Tags" (may take some time)

4. Asset Manager (UPDATED in V2.5)
   - View, update, or clear Dell Asset Tag values directly
   - Useful for IT inventory, service tracking, and post-repair validation
   - Steps:
     - Open the Asset Manager tab
     - The current Asset Tag is displayed automatically
     - Enter a new Asset Tag OR leave blank to clear it
     - Click "Update" to apply the change
     - Reboot to verify the updated Asset Tag

5. Dell PFS BIOS Extractor (NEW in V2.5)
   - Extracts official Dell BIOS Update Packages (.EXE and .RCV)
   - Automatically creates an output folder next to the BIOS file:

         <same_directory>\<filename>_EXTRACTED\

   - Automatically opens the extracted folder in Windows Explorer
   - Requires no user selection of the output folder
   - Provides full logging of the extraction process
   - Powered by Dell PFS Update Extractor technology

   Credit:
   This feature is powered by the Dell PFS Update Extractor by Plato Mavropoulos.

------------------------------------------------------------
⚠️ Disclaimer

This tool is provided as-is with no warranty of any kind.
Use at your own risk. The authors and contributors are not responsible
for any data loss, corruption, hardware damage, or other issues that may occur
from the use of this program.

👉 Always back up your BIOS before patching and test in a safe environment.

⚠️ Important Note: Building the EXE with PyInstaller may trigger antivirus
false positives. This is a common issue with Python-packed executables.
If flagged, add an exclusion for the folder or use the raw Python version
(`DellBiosTools.pyw`) instead.

------------------------------------------------------------
📜 License

MIT — free to use, share, and modify

------------------------------------------------------------
Credits

- Original BIOS Unlocker tool by Rex98 & Techshack Cebu
- Research by Dogbert and Asyncritus
- Dell PFS Update Extractor by Plato Mavropoulos
- Python scripts courtesy of chromebreakerdev

------------------------------------------------------------
☕ Support My Work

If this tool has helped you, you can support future development here:

https://www.buymeacoffee.com/chromebreakerdev

Thank you for your support!
