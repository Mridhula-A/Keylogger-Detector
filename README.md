# 🛡️ KEYGUARD SECURITY CENTER

### Windows Keylogger Detection & Security Analysis Dashboard

<p align="center">

**Detect. Analyze. Monitor. Protect.**

A Windows-based cybersecurity application designed to identify suspicious processes, keyboard-monitoring API indicators, startup entries, registry modifications and potentially suspicious files.

</p>

---

## 🚀 Features

| Module | Description |
|---|---|
| 🔍 Process Scanner | Detects suspicious running processes and execution paths. |
| ⌨️ Keyboard API Scanner | Identifies keyboard-monitoring API imports in executable files. |
| 🚀 Startup Scanner | Examines Windows startup entries and folders. |
| 🗂️ Registry Analyzer | Checks Run, RunOnce and Winlogon configurations. |
| 📁 File Scanner | Analyzes suspicious files using hashes and file indicators. |

### 📊 Security Dashboard
- Dark theme with neon-green design.
- Real-time scan results and security status.
- Total scans, analyzed items and suspicious item statistics.
- Last scan information.

### 🗄️ Scan History & Reports
- SQLite-based scan history.
- Search and filter previous scans.
- View individual scan reports.
- Download JSON reports.
- Export scan history to CSV.
- Delete individual records or clear all history.
- Automatic dashboard statistics updates.

---

## 🧰 Tech Stack

- **Backend:** Python, Flask
- **Frontend:** HTML5, CSS3, JavaScript
- **Database:** SQLite
- **Libraries:** psutil, pefile
- **Platform:** Windows 10/11

---

## 🏗️ Project Structure

```text
Keylogger-Detector/
│
├── app.py
├── database.py
├── scanner.py
├── keyboard_scanner.py
├── startup_scanner.py
├── registry_scanner.py
├── file_scanner.py
├── requirements.txt
├── README.md
│
├── templates/
│   └── index.html
│
└── static/
    ├── css/
    │   └── style.css
    └── js/
        └── script.js
```

---

## ⚙️ Installation & Setup

**1. Clone the repository**

```bash
git clone https://github.com/YOUR-USERNAME/Keylogger-Detector.git
cd Keylogger-Detector
```

**2. Create and activate virtual environment**

```bash
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**3. Install dependencies**

```bash
pip install -r requirements.txt
```

**4. Start the application**

```bash
python app.py
```

**5. Open in browser**

`http://127.0.0.1:5000`

---

## 🔌 API Endpoints

| Endpoint | Function |
|---|---|
| `/api/scan` | Process Scanner |
| `/api/keyboard-scan` | Keyboard API Scanner |
| `/api/startup-scan` | Startup Scanner |
| `/api/registry-scan` | Registry Analyzer |
| `/api/file-scan` | File Scanner |
| `/api/history` | Scan History |
| `/api/dashboard-stats` | Dashboard Statistics |
| `/api/history/clear` | Clear Scan History |

---

## 🔐 Security Approach

KeyGuard uses heuristic-based analysis to identify potentially suspicious system activity.

- Read-only Registry inspection.
- Static executable import analysis.
- SHA-256 file hashing.
- No keystroke recording.
- No execution of scanned files.

**Note:** Detection indicators do not guarantee that an item is malicious or safe. This project is an educational defensive security tool, not a replacement for antivirus software.

---

## 🔮 Future Enhancements

- Advanced behavioral analysis.
- Threat intelligence integration.
- Digital signature verification.
- YARA-based scanning.
- Improved detection accuracy.

---

## 👩‍💻 Developer

**Mridhula A**
---

<p align="center">

### 🛡️ KEYGUARD SECURITY CENTER

**Detect. Analyze. Monitor. Protect.**

Built with ❤️ using Python, Flask & SQLite.

</p>
