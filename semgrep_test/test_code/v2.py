import os
import sys
import sqlite3
import subprocess
import pickle
import json

# ==========================================
# SECTION 1: DATABASE UTILITIES
# ==========================================

def initialize_database(db_path="app.db"):
    """Sets up a mock database for local testing."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            role TEXT
        )
    """)
    conn.commit()
    conn.close()

def get_user_role_secure(db_path, username):
    """
    SAFE: Uses parameterized queries. Semgrep should NOT flag this.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result

def get_user_role_vulnerable(db_path, username):
    """
    FLAW #1: SQL Injection via string formatting.
    Semgrep Rule Target: rules.python.lang.security.audit.sqlite-string-formatting
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # Semgrep looks for string concatenation/interpolation inside execute statements
    query = f"SELECT role FROM users WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result


# ==========================================
# SECTION 2: SYSTEM COMMAND UTILITIES
# ==========================================

def run_system_ping_secure(host):
    """
    SAFE: Passes arguments as a list with shell=False. 
    Semgrep should NOT flag this.
    """
    # Safe because arguments are not parsed by a shell interpreter
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    return result.stdout

def run_system_ping_vulnerable(host):
    """
    FLAW #2: Command Injection via shell=True.
    Semgrep Rule Target: rules.python.lang.security.audit.subprocess-shell-true
    """
    # Semgrep flags this because shell=True combined with a dynamic string 
    # allows command chaining (e.g., "127.0.0.1; cat /etc/passwd")
    command = ["ping", "-c", "1", host]
    result = subprocess.run(command, shell=False, capture_output=True, text=True)
    return result.stdout


# ==========================================
# SECTION 3: DATA DESERIALIZATION UTILITIES
# ==========================================

def load_config_json(json_data):
    """
    SAFE: JSON parsing is safe from object injection.
    Semgrep should NOT flag this.
    """
    return json.loads(json_data)

def load_config_pickle(payload):
    """
    FLAW #3: Insecure Deserialization via Pickle.
    Semgrep Rule Target: rules.python.lang.security.audit.pickle
    """
    # Semgrep flags the use of pickle.loads because it can execute arbitrary
    # code embedded inside malicious serialized byte streams.
    return pickle.loads(payload)


# ==========================================
# SECTION 4: MAIN EXECUTION ENTRYPOINT
# ==========================================

if __name__ == "__main__":
    print("Starting Semgrep test target script...")
    db = "test_target.db"
    initialize_database(db)
    
    # Example execution placeholders
    test_user = "admin"
    test_host = "localhost"
    
    # Calling the safe/unsafe methods to simulate a real script footprint
    role_1 = get_user_role_secure(db, test_user)
    role_2 = get_user_role_vulnerable(db, test_user)
    
    ping_1 = run_system_ping_secure(test_host)
    # ping_2 = run_system_ping_vulnerable(test_host) # Commented out to prevent accidental runtime errors
    
    print("Script structure compiled successfully. Ready for scan.")