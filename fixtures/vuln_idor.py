"""Deliberately vulnerable fixture: IDOR / missing authorization.

Maps to RTA Theme 1's most-reported gap (P03's multi-tenancy /statements
example). SAST typically PASSES this -- syntax is clean -- which is exactly why
the constrained LLM gate (G3) targets it.
"""
import sqlite3


def get_tenant_statement(request, tenant_id):
    # Comes straight from the request path. No check that the authenticated
    # user is actually allowed to read THIS tenant's statement (CWE-639/862).
    db = sqlite3.connect("app.db")
    # Parameterised query -> SAST sees nothing wrong here.
    row = db.execute(
        "SELECT * FROM statements WHERE tenant_id = ?", (tenant_id,)
    ).fetchone()
    return row
