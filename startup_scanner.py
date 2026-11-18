
import os
import winreg

# ==========================================
# KEYLOGGER DETECTOR
# WINDOWS STARTUP SCANNER
# ==========================================

STARTUP_REGISTRY_KEYS = [
    (
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run"
    ),
    (
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    ),
    (
        winreg.HKEY_LOCAL_MACHINE,
        r"Software\Microsoft\Windows\CurrentVersion\Run"
    ),
    (
        winreg.HKEY_LOCAL_MACHINE,
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
]

SUSPICIOUS_LOCATIONS = [
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\downloads\\",
    "\\temp\\"
]


# ==========================================
# CHECK SUSPICIOUS PATHS
# ==========================================

def check_suspicious_path(command):

    indicators = []

    command_lower = command.lower()

    for location in SUSPICIOUS_LOCATIONS:

        if location in command_lower:

            indicators.append(
                "Startup command references a commonly abused directory"
            )

            break

    return indicators


# ==========================================
# SCAN REGISTRY STARTUP ENTRIES
# ==========================================

def scan_registry_startup():

    results = []

    for root, key_path in STARTUP_REGISTRY_KEYS:

        try:

            key = winreg.OpenKey(
                root,
                key_path,
                0,
                winreg.KEY_READ
            )

            index = 0

            while True:

                try:

                    name, value, reg_type = winreg.EnumValue(
                        key,
                        index
                    )

                    command = str(value)

                    indicators = check_suspicious_path(command)

                    results.append({

                        "name": name,
                        "command": command,
                        "source": key_path,
                        "type": reg_type,
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

            winreg.CloseKey(key)

        except OSError:
            continue

    return results


# ==========================================
# SCAN STARTUP FOLDERS
# ==========================================

def scan_startup_folders():

    results = []

    startup_folders = [

        os.path.join(
            os.getenv("APPDATA", ""),
            "Microsoft",
            "Windows",
            "Start Menu",
            "Programs",
            "Startup"
        ),

        os.path.join(
            os.getenv("PROGRAMDATA", ""),
            "Microsoft",
            "Windows",
            "Start Menu",
            "Programs",
            "Startup"
        )

    ]

    for folder in startup_folders:

        if not os.path.isdir(folder):
            continue

        try:

            for filename in os.listdir(folder):

                file_path = os.path.join(
                    folder,
                    filename
                )

                indicators = check_suspicious_path(file_path)

                results.append({

                    "name": filename,
                    "path": file_path,
                    "source": "Startup Folder",
                    "indicators": indicators,
                    "risk": (
                        "Needs Investigation"
                        if indicators
                        else "No Obvious Indicator"
                    )

                })

        except PermissionError:
            continue

    return results


# ==========================================
# COMPLETE STARTUP SCAN
# ==========================================

def scan_startup():

    registry_results = scan_registry_startup()

    folder_results = scan_startup_folders()

    all_results = registry_results + folder_results

    suspicious_count = sum(
        1 for item in all_results
        if item["indicators"]
    )

    return {

        "total_entries": len(all_results),

        "registry_entries": len(registry_results),

        "startup_folder_entries": len(folder_results),

        "suspicious_entries": suspicious_count,

        "results": all_results

    }
