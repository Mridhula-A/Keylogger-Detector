
import psutil
import os

# ==========================================
# KEYLOGGER DETECTOR - PROCESS SCANNER
# ==========================================

SUSPICIOUS_LOCATIONS = [
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\downloads\\",
    "\\startup\\"
]


def scan_processes():

    results = []

    total_processes = 0
    suspicious_processes = 0

    for process in psutil.process_iter(
        ['pid', 'name', 'exe', 'username', 'status']
    ):

        try:
            info = process.info

            pid = info.get('pid')
            name = info.get('name') or "Unknown"
            exe = info.get('exe') or "Unavailable"
            username = info.get('username') or "Unknown"
            status = info.get('status') or "Unknown"

            indicators = []
            risk = "Low"

            # Check executable location
            if exe != "Unavailable":

                exe_path = os.path.normcase(exe)

                for location in SUSPICIOUS_LOCATIONS:

                    if location in exe_path.lower():

                        indicators.append(
                            "Executable located in a user-writable or commonly abused directory"
                        )
                        break

            # Assign risk level based on indicators
            if len(indicators) >= 2:
                risk = "High"

            elif len(indicators) == 1:
                risk = "Medium"

            else:
                risk = "Low"

            if risk != "Low":
                suspicious_processes += 1

            results.append({

                "pid": pid,
                "name": name,
                "exe": exe,
                "username": username,
                "status": status,
                "risk": risk,
                "indicators": indicators

            })

            total_processes += 1

        except (psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess):

            continue

    return {

        "total_processes": total_processes,

        "suspicious_processes": suspicious_processes,

        "safe_processes": total_processes - suspicious_processes,

        "processes": results

    }
