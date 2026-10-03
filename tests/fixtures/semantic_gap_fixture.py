"""
Test Fixture: Semantic Security Gap Example
============================================
Contains code patterns with SQL injection and authentication keywords
designed to trigger Phase 5 AI-Need gating (should_call_grok == True)
for SecurityAgent testing.
"""
import os
import sqlite3

def query_user_account(user_input: str):
    """Vulnerable SQL query function with direct concatenation."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL injection vulnerability keyword: sql, auth, exec
    query = "SELECT * FROM auth_users WHERE username = '" + user_input + "'"
    cursor.execute(query)
    return cursor.fetchall()

def execute_admin_cmd(cmd_param: str):
    """Vulnerable command execution function."""
    # Command execution vulnerability keyword: exec, cmd, token
    token = os.getenv("ADMIN_TOKEN", "default_secret_token")
    cmd = f"echo {token} && {cmd_param}"
    os.system(cmd)
