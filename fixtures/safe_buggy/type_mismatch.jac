"""TEST / DEMONSTRATION FIXTURE. A string is passed where an int is required."""

def add_amounts(left: int, right: int) -> int {
    return left + right;
}

def broken_total() -> int {
    return add_amounts("1", 2);
}
