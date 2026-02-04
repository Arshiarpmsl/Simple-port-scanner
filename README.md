# 🔍 Simple Python Port Scanner (Nmap Wrapper)

This is a small port scanning tool I built in Python as part of my learning in Cyber Security.  
It uses the `python-nmap` library to run Nmap scans and then formats the results in a cleaner, more readable way.

This project is mainly for:
- Learning how port scanners work
- Practising Python
- Building something useful for my university / placement portfolio

⚠️ **Legal Warning:**  
Only scan systems that you own or have been given clear permission to scan.  
Scanning networks without permission is illegal.

---

## ✨ Features

- Scan a target IP or hostname
- Custom port ranges (default: 1–1000)
- Service & version detection
- Highlights some potentially insecure services / old versions
- Coloured terminal output
- Save results to a file
- Includes raw Nmap output in saved report

---

## 🧰 Requirements

- Python 3
- Nmap installed on your system

Python libraries:
- `python-nmap`
- `requests`
- `beautifulsoup4`
Screenshots are in screenshots directory

Install dependencies:

```bash
pip install -r requirements.txt


