"""Untrusted-text handling. Target output is data, never a command."""

def bound_text(value: str, limit: int) -> str {
    if limit < 0 {
        limit = 0;
    }
    if len(value) <= limit {
        return value;
    }
    return value[0:limit];
}

def strip_ansi(value: str) -> str {
    out = "";
    i = 0;
    n = len(value);
    while i < n {
        ch = value[i];
        if ch == "\x1b" and i + 1 < n and value[i + 1] == "[" {
            i += 2;
            while i < n {
                code = ord(value[i]);
                i += 1;
                if code >= 64 and code <= 126 {
                    break;
                }
            }
            continue;
        }
        o = ord(ch);
        if o == 9 or o == 10 or o == 13 or (o >= 32 and o != 127) {
            out += ch;
        }
        i += 1;
    }
    return out;
}

def sanitize_token(value: str, limit: int) -> str {
    cleaned = "";
    for ch in strip_ansi(value) {
        o = ord(ch);
        ok = (o >= 48 and o <= 57) or (o >= 65 and o <= 90) or (o >= 97 and o <= 122);
        if ok or ch == "_" or ch == "-" or ch == "." or ch == ":" or ch == "+" {
            cleaned += ch;
        } elif o >= 32 {
            cleaned += "_";
        }
    }
    cleaned = bound_text(cleaned, limit);
    if cleaned == "" {
        return "-";
    }
    return cleaned;
}

def is_hex_id(value: str) -> bool {
    if len(value) < 8 or len(value) > 64 {
        return False;
    }
    for ch in value {
        ok = (ch >= "0" and ch <= "9") or (ch >= "a" and ch <= "f");
        if not ok {
            return False;
        }
    }
    return True;
}

def contains_forbidden_claim(text: str) -> str {
    lowered = text.lower();
    banned = ["cve-", "cvss", "zero-day", "zeroday", "critical vulnerability", "exploitability score"];
    for word in banned {
        if word in lowered {
            return word;
        }
    }
    return "";
}

test "sanitize drops ansi and markup" {
    raw = "\x1b[31m<script>alert(1)</script>../etc/passwd";
    token = sanitize_token(raw, 80);
    assert "\x1b" not in token;
    assert "<" not in token;
    assert "/" not in token;
    assert token != "";
}

test "hex ids reject traversal" {
    assert is_hex_id("4cc17bc3b746efda");
    assert not is_hex_id("../etc/passwd");
    assert not is_hex_id("4CC17BC3");
    assert not is_hex_id("");
}

test "forbidden claims are detectable" {
    assert contains_forbidden_claim("assigned CVE-2026-0001") == "cve-";
    assert contains_forbidden_claim("No control-flow hijack was demonstrated.") == "";
}
