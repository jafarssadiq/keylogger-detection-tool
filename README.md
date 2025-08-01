# Advanced Keylogger Detection Tool

🔒 A Python-based cybersecurity project to detect keyloggers, built to deepen my malware analysis skills. Tested ethically on my own system for educational purposes only.

## Overview
This tool detects keyloggers by monitoring processes, files, network activity, and file modifications. It features a sleek console interface, desktop notifications, and interactive threat mitigation, making it both functional and professional.

## Features
- 🔍 **Process Monitoring**: Detects suspicious Python processes using `pynput` or `keyboard` with `psutil`.
- 📂 **File Scanning**: Finds keylogger files (e.g., `keylog.txt`, `server_log.txt`).
- 🌐 **Network Monitoring**: Identifies potential data exfiltration connections.
- 🔔 **Real-Time Alerts**: Sends desktop notifications via `plyer`.
- 📊 **Visual Output**: Displays results in colorful tables using `rich`.
- 📜 **JSON Logging**: Saves findings to `detection_log.json` for analysis.
- ⚡ **Interactive Actions**: Prompts to terminate processes or delete files.

## How It Works
1. **Keylogger (keylogger.py)**: A test keylogger (for learning) logs keystrokes to `keylog.txt` and simulates data transmission to `server_log.txt`. Stops with `Esc` key.
2. **Detector (advanced_keylogger_detector.py)**: Scans for:
   - Processes using `pynput` (e.g., `keylogger.py`).
   - Suspicious files and recent modifications.
   - Active network connections.
3. Outputs findings in console tables, notifications, and JSON logs, with options to terminate threats.

## Setup
1. Clone the repo:
   ```bash
   git clone https://github.com/yourusername/your-repo-name.git

Install dependencies:
bashpip install psutil rich plyer

Run the detector:
bashpython advanced_keylogger_detector.py

(Optional) Run the test keylogger to simulate threats:
bashpython keylogger.py


Usage

Run keylogger.py in one terminal (VS Code) to simulate a keylogger.
Run advanced_keylogger_detector.py in another terminal.
Watch for colorful tables, notifications, and prompts to terminate processes or delete files.
Stop with Ctrl+C (detector) or Esc (keylogger).
Check detection_log.json for structured logs.

Example Output
json{"timestamp": "2025-08-01T15:17:00", "level": "INFO", "message": "Suspicious file found: ./keylog.txt"}
Console table:
text+--------------+------------------+
| File Path    | Action           |
+--------------+------------------+
| ./keylog.txt | Prompt to delete |
+--------------+------------------+
Ethical Note
This project is for educational purposes only, tested on my own system/virtual machine. Unauthorized use of keyloggers is illegal and unethical. Always obtain consent before monitoring systems.
Future Enhancements

Add a GUI with tkinter for a desktop app experience.
Generate reports from JSON logs.
Expand network analysis for specific protocols (e.g., SMTP).

Contributing
Feedback and contributions are welcome! Open an issue or PR to improve the tool.
License
MIT License
