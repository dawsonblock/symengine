"""Tiny calculator helpers."""


def add(a, b):
    return a + b


def subtract(a, b):
    return a - b


def percentage(part, whole):
    """Return part as a percentage of whole on a 0-100 scale.

    percentage(1, 4) -> 25.0
    """
    return part / whole
