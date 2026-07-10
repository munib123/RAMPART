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

def run_system_ping_vulnerable(host):
    """
    FLAW #2: Command Injection via shell=True.
    Semgrep Rule Target: rules.python.lang.security.audit.subprocess-shell-true
    """
    # Semgrep flags this because shell=True combined with a dynamic string 
    # allows command chaining (e.g., "127.0.0.1; cat /etc/passwd")
    command = f"ping -c 1 {host}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def load_config_pickle(payload):
    """
    FLAW #3: Insecure Deserialization via Pickle.
    Semgrep Rule Target: rules.python.lang.security.audit.pickle
    """
    # Semgrep flags the use of pickle.loads because it can execute arbitrary
    # code embedded inside malicious serialized byte streams.
    return pickle.loads(payload)

def execute_command():
    command = input("Enter a command: ")

    # Dangerous: user input is executed by the shell
    subprocess.run(command, shell=True)