# Free-Data-Recovery-Tool

#Free Data Recovery Tool (Python GUI)
A cross-platform logical data recovery & file analysis tool built using Python + Tkinter, designed for educational and non-forensic use.
This tool scans folders, analyzes files, detects duplicates using hashing, visualizes file statistics, and allows selective recovery with exportable reports.

Features
✔ Cross-platform (Windows / Linux / macOS)
✔ Modern GUI using Tkinter
✔ Light / Dark mode toggle
✔ Logical file scanning (non-destructive)
✔ File type filtering (PDF, Images, Videos, Docs, Audio, ZIP)
✔ Real-time progress bar
✔ File search support
✔ File recovery (copy-based)
✔ MD5 & SHA256 hash calculation
✔ Duplicate file detection
✔ Scan statistics pie chart
✔ Export scan report (CSV & PDF)
✔ OS auto-detection

Supported Operating Systems
OS

| OS                            | Status      |
| ----------------------------- | ----------- |
| Windows 10 / 11               | ✅ Supported |
| Linux (Ubuntu, Kali, etc.)    | ✅ Supported |
| macOS (Intel & Apple Silicon) | ✅ Supported |

Note: This is a logical recovery tool, not a forensic or raw disk recovery solution.

#Requirements
Python 3.9 or higher
pip (Python package manager)

#Installation (All OS)

#Clone the Repository
git clone https://github.com/Ashwinhacker/Free-Data-Recovery-Tool.git
cd data-recovery-tool

#Create Virtual Environment (Recommended)
Windows
python -m venv venv
venv\Scripts\activate
Linux / macOS
python3 -m venv venv
source venv/bin/activate

#Install Dependencies
pip install matplotlib reportlab
Tkinter comes pre-installed with Python on most systems.
#Run the Tool
python data_recovery_tool.py
(or)
python3 data_recovery_tool.py

How It Works
Click Scan Folder
Select any directory
Tool scans files logically (no disk writes)
Hashes files (MD5 & SHA256)
Displays results in table
Use:
Recover → copy selected files
Duplicates → detect duplicate groups
Pie Chart → visualize file types
Export CSV / PDF → generate reports


Disclaimer
This tool is intended for:
✅ Educational use
✅ College projects
✅ Personal file analysis
❌ Not for forensic evidence
❌ Not for illegal recovery
❌ No raw disk access


Author
Ashwin Kumar
Cyber Security || CEH ||Ethical Hacker| Python Developer | 



