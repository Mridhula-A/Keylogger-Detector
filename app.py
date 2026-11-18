
import json

from flask import Flask, jsonify, render_template

from scanner import scan_processes
from keyboard_scanner import scan_keyboard_indicators
from startup_scanner import scan_startup
from registry_scanner import scan_registry
from file_scanner import scan_files

from database import initialize_database, get_connection


app = Flask(__name__)

initialize_database()


# ==========================================
# SAVE SCAN HISTORY
# ==========================================

def save_scan_history(scanner_name, results):

    total_items = (
        results.get("total_processes")
        or results.get("files_scanned")
        or results.get("total_entries")
        or results.get("total_scanned")
        or 0
    )

    suspicious_count = (
        results.get("suspicious_processes")
        or results.get("indicator_count")
        or results.get("suspicious_entries")
        or results.get("suspicious_files")
        or 0
    )

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO scan_history (
                scanner_name,
                scan_status,
                total_items,
                suspicious_count,
                report_json
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                scanner_name,
                "COMPLETED",
                total_items,
                suspicious_count,
                json.dumps(results, default=str)
            )
        )

        connection.commit()

    finally:
        connection.close()


# ==========================================
# COMMON SCAN RESPONSE
# ==========================================

def successful_scan(scanner_name, results):

    try:
        save_scan_history(scanner_name, results)

    except Exception as error:
        print("Database history save error:", error)

    return jsonify({
        "success": True,
        "scanner": scanner_name,
        "data": results
    })


# ==========================================
# HOME ROUTE
# ==========================================

@app.route("/")
def home():
    return render_template("index.html")


# ==========================================
# PROCESS SCANNER
# ==========================================

@app.route("/api/scan")
def process_scan():

    try:
        return successful_scan(
            "Process Scanner",
            scan_processes()
        )

    except Exception as error:
        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


# ==========================================
# KEYBOARD API SCANNER
# ==========================================

@app.route("/api/keyboard-scan")
def keyboard_scan():

    try:
        return successful_scan(
            "Keyboard API Indicator Scanner",
            scan_keyboard_indicators()
        )

    except Exception as error:
        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


# ==========================================
# STARTUP SCANNER
# ==========================================

@app.route("/api/startup-scan")
def startup_scan():

    try:
        return successful_scan(
            "Windows Startup Scanner",
            scan_startup()
        )

    except Exception as error:
        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


# ==========================================
# REGISTRY SECURITY SCANNER
# ==========================================

@app.route("/api/registry-scan")
def registry_scan():

    try:
        return successful_scan(
            "Registry Security Scanner",
            scan_registry()
        )

    except Exception as error:
        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


# ==========================================
# SUSPICIOUS FILE SCANNER
# ==========================================

@app.route("/api/file-scan")
def file_scan():

    try:
        return successful_scan(
            "Suspicious File Scanner",
            scan_files()
        )

    except Exception as error:
        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


# ==========================================
# VIEW SCAN HISTORY
# ==========================================

@app.route("/api/history")
def scan_history():

    connection = None

    try:
        connection = get_connection()

        cursor = connection.execute("""
            SELECT
                id,
                scanner_name,
                scan_status,
                total_items,
                suspicious_count,
                scan_date,
                report_json
            FROM scan_history
            ORDER BY id DESC
        """)

        history = [dict(row) for row in cursor.fetchall()]

        return jsonify({
            "success": True,
            "total_records": len(history),
            "history": history
        })

    except Exception as error:
        return jsonify({
            "success": False,
            "message": str(error)
        }), 500

    finally:
        if connection:
            connection.close()


# ==========================================
# DELETE INDIVIDUAL SCAN HISTORY
# ==========================================

@app.route("/api/history/<int:scan_id>", methods=["DELETE"])
def delete_scan_history(scan_id):

    connection = None

    try:
        connection = get_connection()

        cursor = connection.execute(
            "DELETE FROM scan_history WHERE id = ?",
            (scan_id,)
        )

        connection.commit()

        if cursor.rowcount == 0:
            return jsonify({
                "success": False,
                "message": "Scan history record not found."
            }), 404

        return jsonify({
            "success": True,
            "message": "Scan history deleted successfully."
        })

    except Exception as error:
        return jsonify({
            "success": False,
            "message": str(error)
        }), 500

    finally:
        if connection:
            connection.close()


# ==========================================
# CLEAR ALL SCAN HISTORY
# ==========================================

@app.route("/api/history/clear", methods=["DELETE"])
def clear_scan_history():

    connection = None

    try:
        connection = get_connection()

        cursor = connection.execute(
            "DELETE FROM scan_history"
        )

        deleted_count = cursor.rowcount

        connection.commit()

        return jsonify({
            "success": True,
            "deleted_count": deleted_count,
            "message": "All scan history cleared successfully."
        })

    except Exception as error:
        return jsonify({
            "success": False,
            "message": str(error)
        }), 500

    finally:
        if connection:
            connection.close()


# ==========================================
# DATABASE-BACKED DASHBOARD STATISTICS
# ==========================================

@app.route("/api/dashboard-stats")
def dashboard_stats():

    connection = None

    try:
        connection = get_connection()

        stats = connection.execute("""
            SELECT
                COUNT(*) AS total_scans,
                COALESCE(SUM(total_items), 0) AS total_items,
                COALESCE(SUM(suspicious_count), 0) AS suspicious_items,
                COALESCE(
                    SUM(
                        CASE
                            WHEN suspicious_count > 0 THEN 1
                            ELSE 0
                        END
                    ), 0
                ) AS flagged_scans
            FROM scan_history
        """).fetchone()

        scanner_stats = connection.execute("""
            SELECT
                scanner_name,
                COUNT(*) AS scan_count
            FROM scan_history
            GROUP BY scanner_name
            ORDER BY scan_count DESC
        """).fetchall()

        return jsonify({
            "success": True,
            "statistics": dict(stats),
            "scanner_stats": [
                dict(row) for row in scanner_stats
            ]
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500

    finally:
        if connection:
            connection.close()


# ==========================================
# START APPLICATION
# ==========================================

if __name__ == "__main__":
    app.run(debug=True)
