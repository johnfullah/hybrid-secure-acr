"""Deliberately vulnerable fixture: hard-coded secret (CWE-798) - Gate 0 target.

NOTE FOR REVIEWERS: these are FAKE credentials created solely to exercise the
secret-scanning gate for the dissertation prototype. They are not live and grant
no access. They are deliberately NOT the AWS documented example key
(AKIAIOSFODNN7EXAMPLE), because Gitleaks allowlists that value, which would
suppress the very detection this fixture is meant to demonstrate.
"""

# Fake AWS access key id (valid FORMAT, random body -> triggers gitleaks aws rule)
AWS_ACCESS_KEY_ID = "AKIA5R7HTQ2XZL9K4MWP"
# Fake AWS secret access key (40-char base64-ish -> triggers gitleaks generic/aws)
AWS_SECRET_ACCESS_KEY = "wJalr2XuTn8fBk7MDENGbPxRfi9Ev4Hd0Qz2LmNa"
# Hard-coded DB password (triggers bandit B105 and generic secret rules)
DB_PASSWORD = "sup3rs3cr3t_pr0duction_pw"


def connect():
    return (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, DB_PASSWORD)
