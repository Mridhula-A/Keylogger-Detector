
import winreg
import os

# ==========================================
# KEYLOGGER DETECTOR
# REGISTRY SECURITY ANALYZER
# ==========================================

RUN_KEYS = [
    (
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU Run"
    ),
    (
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU RunOnce"
    ),
    (
        winreg.HKEY_LOCAL_MACHINE,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM Run"
    ),
    (
        winreg.HKEY_LOCAL_MACHINE,
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM RunOnce"
    )
]

WINLOGON_KEY = (
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
)

SUSPICIOUS_PATHS = [
    r"\appdata\local\temp",
    r"\appdata\roaming",
    r"\downloads",
    r"\temp"
]


# ==========================================
# PATH ANALYSIS
# ==========================================

def analyze_command(command):

    indicators = []

    command_lower = str(command).lower().replace("/", "\\")

    for path in SUSPICIOUS_PATHS:

        if path in command_lower:

            indicators.append(
                "Command references a commonly abused directory"
            )

            break

    return indicators


# ==========================================
# SCAN RUN AND RUNONCE ENTRIES
# ==========================================

def scan_run_entries():

    results = []

    for root, path, source in RUN_KEYS:

        try:

            with winreg.OpenKey(
                root,
                path,
                0,
                winreg.KEY_READ
            ) as key:

                index = 0

                while True:

                    try:

                        name, value, reg_type = winreg.EnumValue(
                            key,
                            index
                        )

                        command = str(value)

                        indicators = analyze_command(command)

                        results.append({

                            "name": name,
                            "command": command,
                            "source": source,
                            "indicators": indicators,
                            "risk": (
                                "Needs Investigation"
                                if indicators
                                else "No Obvious Indicator"
                            )

                        })

                        index += 1

                    except OSError:
                        break

        except OSError:
            continue

    return results


# ==========================================
# SCAN WINLOGON SETTINGS
# ==========================================

def scan_winlogon():

    results = []

    expected_values = {
        "Shell": "explorer.exe",
        "Userinit": "userinit.exe"
    }

    try:

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            WINLOGON_KEY,
            0,
            winreg.KEY_READ
        ) as key:

            for value_name, expected in expected_values.items():

                try:

                    value, reg_type = winreg.QueryValueEx(
                        key,
                        value_name
                    )

                    actual = str(value).strip()

                    # Remove surrounding quotes and split
                    # comma-separated executable paths.

                    actual_names = [
                        os.path.basename(
                            part.strip().strip('"').strip()
                        ).lower()
                        for part in actual.split(",")
                        if part.strip()
                    ]

                    matches = (
                        len(actual_names) == 1
                        and actual_names[0] == expected
                    )

                    indicators = []

                    if not matches:

                        indicators.append(
                            "Winlogon value differs from the basic expected configuration"
                        )

                    results.append({

                        "name": value_name,
                        "value": actual,
                        "source": "Winlogon",
                        "indicators": indicators,
                        "risk": (
                            "Needs Investigation"
                            if indicators
                            else "No Obvious Indicator"
                        )

                    })

                except FileNotFoundError:

                    results.append({

                        "name": value_name,
                        "value": "Not Found",
                        "source": "Winlogon",
                        "indicators": [
                            "Expected registry value is missing"
                        ],
                        "risk": "Needs Investigation"

                    })

    except OSError:

        results.append({

            "name": "Winlogon",
            "value": "Unavailable",
            "source": "Registry",
            "indicators": [
                "Unable to inspect Winlogon registry key"
            ],
            "risk": "Scan Incomplete"

        })

    return results


# ==========================================
# COMPLETE REGISTRY SCAN
# ==========================================

def scan_registry():

    run_results = scan_run_entries()

    winlogon_results = scan_winlogon()

    all_results = run_results + winlogon_results

    suspicious_count = sum(
        1 for item in all_results
        if item["indicators"]
    )

    return {

        "total_entries": len(all_results),

        "run_entries": len(run_results),

        "winlogon_entries": len(winlogon_results),

        "suspicious_entries": suspicious_count,

        "results": all_results

    }
