
import os
import hashlib
import datetime

# ==========================================
# KEYLOGGER DETECTOR
# SUSPICIOUS FILE SCANNER
# ==========================================

EXECUTABLE_EXTENSIONS = [
    ".exe",
    ".dll",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1"
]

SUSPICIOUS_LOCATIONS = [
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\downloads\\",
    "\\temp\\"
]


# ==========================================
# GENERATE SHA256 HASH
# ==========================================

def calculate_hash(file_path):

    sha256 = hashlib.sha256()

    try:

        with open(file_path, "rb") as file:

            for chunk in iter(
                lambda: file.read(4096),
                b""
            ):

                sha256.update(chunk)

        return sha256.hexdigest()

    except OSError:

        return "Unavailable"


# ==========================================
# CHECK FILE INDICATORS
# ==========================================

def analyze_file(file_path):

    indicators = []

    path_lower = file_path.lower()

    filename = os.path.basename(file_path)

    # Check executable location
    for location in SUSPICIOUS_LOCATIONS:

        if location in path_lower:

            indicators.append(
                "Executable located in a commonly abused directory"
            )

            break

    # Check hidden file attribute on Windows
    try:

        attributes = os.stat(file_path).st_file_attributes

        if attributes & 2:

            indicators.append(
                "Hidden file attribute detected"
            )

    except (AttributeError, OSError):
        pass

    return indicators


# ==========================================
# SCAN EXECUTABLE FILES
# ==========================================

def scan_files(scan_directory=None):

    if scan_directory is None:

        scan_directory = os.path.join(
            os.environ.get("LOCALAPPDATA", ""),
            "Temp"
        )

    results = []

    total_scanned = 0

    suspicious_count = 0

    if not os.path.isdir(scan_directory):

        return {

            "success": False,
            "message": "Scan directory does not exist",
            "total_scanned": 0,
            "suspicious_files": 0,
            "results": []

        }

    for root, dirs, files in os.walk(scan_directory):

        # Avoid following directory junctions and symlinks
        dirs[:] = [
            d for d in dirs
            if not os.path.islink(os.path.join(root, d))
        ]

        for filename in files:

            extension = os.path.splitext(filename)[1].lower()

            if extension not in EXECUTABLE_EXTENSIONS:
                continue

            file_path = os.path.join(root, filename)

            if os.path.islink(file_path):
                continue

            try:

                metadata = os.stat(file_path)

                file_size = metadata.st_size

                modified = datetime.datetime.fromtimestamp(
                    metadata.st_mtime
                ).strftime("%Y-%m-%d %H:%M:%S")

                file_hash = calculate_hash(file_path)

                indicators = analyze_file(file_path)

                total_scanned += 1

                if indicators:
                    suspicious_count += 1

                results.append({

                    "name": filename,
                    "path": file_path,
                    "extension": extension,
                    "size_bytes": file_size,
                    "modified": modified,
                    "sha256": file_hash,
                    "indicators": indicators,
                    "risk": (
                        "Needs Investigation"
                        if indicators
                        else "No Obvious Indicator"
                    )

                })

            except OSError:
                continue

    return {

        "success": True,
        "scan_directory": scan_directory,
        "total_scanned": total_scanned,
        "suspicious_files": suspicious_count,
        "results": results

    }
