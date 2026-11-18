
import psutil
import pefile
import os

# ==========================================
# KEYLOGGER DETECTOR
# KEYBOARD API INDICATOR SCANNER
# ==========================================

KEYBOARD_APIS = [
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "GetAsyncKeyState",
    "GetKeyState",
    "RegisterRawInputDevices"
]


def inspect_executable(file_path):

    detected_apis = []

    try:
        if not os.path.isfile(file_path):
            return detected_apis

        # Read Windows executable structure
        pe = pefile.PE(file_path, fast_load=True)

        # Parse executable import information
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY[
                    "IMAGE_DIRECTORY_ENTRY_IMPORT"
                ]
            ]
        )

        # Inspect imported API names
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):

            for entry in pe.DIRECTORY_ENTRY_IMPORT:

                for imported_function in entry.imports:

                    if imported_function.name:

                        api_name = imported_function.name.decode(
                            "utf-8", errors="ignore"
                        )

                        if api_name in KEYBOARD_APIS:
                            detected_apis.append(api_name)

        pe.close()

    except Exception:
        pass

    return list(set(detected_apis))


# ==========================================
# SCAN RUNNING PROCESSES
# ==========================================

def scan_keyboard_indicators():

    results = []
    scanned_files = set()
    total_scanned = 0

    for process in psutil.process_iter(
        ["pid", "name", "exe"]
    ):

        try:
            info = process.info

            pid = info.get("pid")
            name = info.get("name") or "Unknown"
            exe = info.get("exe")

            if not exe or exe in scanned_files:
                continue

            scanned_files.add(exe)

            detected = inspect_executable(exe)

            total_scanned += 1

            if detected:

                results.append({

                    "pid": pid,
                    "process": name,
                    "executable": exe,
                    "detected_apis": detected,
                    "risk": "Needs Investigation"

                })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return {

        "files_scanned": total_scanned,

        "indicator_count": len(results),

        "results": results

    }
