
import sqlite3
import os

# ==========================================
# KEYGUARD DATABASE CONFIGURATION
# ==========================================

DATABASE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "keyguard.db"
)


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_connection():

    connection = sqlite3.connect(DATABASE_PATH)

    connection.row_factory = sqlite3.Row

    return connection


# ==========================================
# INITIALIZE DATABASE
# ==========================================

def initialize_database():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            scanner_name TEXT NOT NULL,

            scan_status TEXT NOT NULL,

            total_items INTEGER DEFAULT 0,

            suspicious_count INTEGER DEFAULT 0,

            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            report_json TEXT

        )
    """)

    connection.commit()

    connection.close()

    print("KeyGuard database initialized successfully!")


# ==========================================
# TEST DATABASE
# ==========================================

if __name__ == "__main__":

    initialize_database()

    print("Database location:", DATABASE_PATH)
