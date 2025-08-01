# keylogger-detection-tool
i created a keylogger detection tool 
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
