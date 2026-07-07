"""Clean fixture: should PASS all gates (no findings)."""


def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b


def greet(name: str) -> str:
    return f"Hello, {name}!"
