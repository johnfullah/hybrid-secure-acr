"""Deliberately vulnerable fixture: SQL injection (CWE-89).

This is a SYNTACTIC pattern -- RTA Theme 1 says SAST handles these well, so G1
(Bandit/Semgrep) is expected to flag it. Included to show the SAST gate working.
"""
import sqlite3


def find_user(username):
    db = sqlite3.connect("app.db")
    # String concatenation into SQL -> classic injection, deterministic detect.
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return db.execute(query).fetchone()
