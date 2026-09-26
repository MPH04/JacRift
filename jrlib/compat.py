"""Load a legacy campaign document into the JacRift state name.

vectorrift.state.v1 stays on disk for the synthetic fuzzer. Readers that want
the current name use this loader. The fuzzer does not rewrite old files.
"""

from __future__ import annotations


def load_campaign_state(document: dict) -> dict:
    if not isinstance(document, dict):
        raise TypeError("campaign state must be an object")
    schema = document.get("schema")
    if schema == "jacrift.state.v2":
        return document
    if schema != "vectorrift.state.v1":
        raise ValueError("unsupported campaign schema")
    converted = dict(document)
    converted["schema"] = "jacrift.state.v2"
    converted["compat_from"] = "vectorrift.state.v1"
    return converted
