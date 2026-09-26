"""TEST / DEMONSTRATION FIXTURE. Deterministic index exception."""

def explode() -> str {
    items: list[str] = [];
    return items[0];
}

with entry {
    explode();
}
