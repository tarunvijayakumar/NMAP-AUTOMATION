# NMAP-AUTOMATION

====================================================================================================================================================================================================================
                                                                                    Excel-based OS Detection Scanner
                                                                                   ----------------------------------
                                                                         A GUI-based Python tool for scanning IPs from Excel
                                                                          and detecting their operating systems using Nmap.
====================================================================================================================================================================================================================

FEATURES
-----------
- Accepts Excel (.xlsx) files with IP address column.
- Performs OS detection using Nmap (-O).
- Scans top 100 ports for speed.
- Categorizes detected hosts into Windows and Others.
- Saves each scan result into a separate text file.
- GUI with real-time scanning log.

INPUT FORMAT
---------------
Excel file must have a column named: IP

Example:
--------
| IP             |
|----------------|
| 192.168.1.1    |
| 10.0.0.1       |
| 172.16.0.100   |
| 192.168.10.0/24|

 Both single IPs and CIDR notations are supported.

HOW TO RUN
-------------
1. Install requirements:
   > pip install pandas openpyxl python-nmap

2. Ensure Nmap is installed on your system.
   - Windows: https://nmap.org/download.html#windows
   - Linux:
     > sudo apt update
     > sudo apt install nmap
   - macOS:
     > brew install nmap

3. Run the script:
   > python scanner.py

4. In the GUI:
   - Click '📂 Select Excel & Start Scan'
   - Choose Excel file with IPs
   - Choose output folder
   - Watch scanning progress in real-time

OUTPUT FILES
---------------
Each scanned IP/subnet creates a text file with:
- OS classification (Windows/Other)
- Open ports and service names
- OS match accuracy and fingerprint info
- Raw Nmap scan data

BEHIND THE SCENES
--------------------
Nmap Command Used:
> nmap -O -T4 -sT --top-ports 100 <target>

Flags:
- -O  : Enable OS detection
- -T4 : Faster execution
- -sT : TCP Connect Scan (safe for non-root)
- --top-ports 100 : Scan top 100 common ports

CUSTOM NMAP COMMAND SUPPORT
------------------------------
This tool supports custom Nmap scan arguments.

🔧 How to Use:
- In the GUI, enter your desired Nmap arguments (e.g., -sS -O -p 21,22,80) into the input field.
- Leave it blank to use the default: -O -T4 -sT --top-ports 100

Examples:
- -O --top-ports 50             → OS detection with top 50 ports
- -sS -O -T3                    → SYN scan with OS detection (slightly slower)
- -O -p 21,22,80,443            → Only scan FTP, SSH, HTTP, HTTPS
- -O -v                        → Verbose OS detection
- (leave empty)                → Use default arguments

Why Custom Scans?
- Lets you tune performance and accuracy
- Target specific services
- Perform stealthier or more aggressive scans


AUTHOR
-----------
Tarun V  
Cybersecurity Student 

                                                                    This tool is intended for educational and internal
                                                                     auditing purposes only. Unauthorized scanning is
                                                                                  illegal and unethical.

====================================================================================================================================================================================================================
