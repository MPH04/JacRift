#include "vr_target.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Intentionally vulnerable local demo target.
   Bugs are confined to this process and are the campaign's subject:
   - trusted length field causes an out-of-bounds read (AddressSanitizer)
   - signed 32-bit multiply overflows (UndefinedBehaviorSanitizer)
   - 'D' before authentication breaks a state invariant without a memory error
   - 'N' selects a semantic label with no extra control flow, so behavior
     can change while SanitizerCoverage edges stay flat
   This is not an exploit. There is no network listener and no credential. */

const char *vr_target_id(void) { return "riftpacket"; }
const char *vr_target_version(void) { return "demo-1"; }

enum { ST_CLOSED = 0, ST_OPEN, ST_AUTH, ST_DATA };

static const char *state_name(int st) {
    switch (st) {
    case ST_OPEN: return "OPEN";
    case ST_AUTH: return "AUTH";
    case ST_DATA: return "DATA";
    default: return "CLOSED";
    }
}

__attribute__((noinline)) static const char *note_label(uint8_t b) {
    static const char *labels[8] = {"alpha", "beta", "gamma", "delta",
                                     "epsilon", "zeta", "eta", "theta"};
    return labels[b & 7];
}

__attribute__((noinline)) static void transit(int *st, int next) {
    vr_emit("transition", state_name(*st), state_name(next));
    *st = next;
}

__attribute__((noinline)) static uint8_t consume_length(const uint8_t *data, size_t n, size_t *i) {
    if (*i + 2 > n) {
        vr_emit("reject", "short_length", "-");
        return 0;
    }
    uint32_t len = ((uint32_t)data[*i] << 8) | (uint32_t)data[*i + 1];
    *i += 2;
    vr_emit("op", "length", "-");
    /* BUG: `len` is trusted. The loop reads past the heap object when
       len exceeds the bytes that remain. ASan reports this; we do not
       turn it into a write primitive. */
    volatile uint8_t sink = 0;
    for (uint32_t k = 0; k < len; k++) {
        sink = (uint8_t)(sink + data[*i + k]);
    }
    if (*i + len > *i) {
        *i += len;
    }
    return sink;
}

__attribute__((noinline)) static int32_t load_be_i32(const uint8_t *p) {
    uint32_t u = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    return (int32_t)u;
}

__attribute__((noinline)) static int32_t apply_scale(int32_t a, int32_t b) {
    /* BUG: signed overflow is undefined. UBSan aborts when the product
       does not fit in int32. The result is only observed, never used as
       a jump target. */
    return a * b;
}

static void consume_scale(const uint8_t *data, size_t n, size_t *i) {
    if (*i + 8 > n) {
        vr_emit("reject", "short_scale", "-");
        return;
    }
    int32_t a = load_be_i32(data + *i);
    int32_t b = load_be_i32(data + *i + 4);
    *i += 8;
    vr_emit("op", "scale", "-");
    int32_t c = apply_scale(a, b);
    vr_emit("semantic", "scale", c == 0 ? "zero" : "nonzero");
}

static int parse_packet(const uint8_t *data, size_t n) {
    if (n < 2 || data == NULL || data[0] != 'V' || data[1] != 'R') {
        vr_emit("reject", "magic", "-");
        return 0;
    }
    vr_emit("op", "magic", "-");
    int st = ST_CLOSED;
    size_t i = 2;
    while (i < n) {
        uint8_t op = data[i++];
        if (op == 'O') {
            vr_emit("op", "open", "-");
            transit(&st, ST_OPEN);
        } else if (op == 'A') {
            if (i + 4 > n) {
                vr_emit("reject", "short_auth", "-");
                break;
            }
            i += 4;
            vr_emit("op", "auth", "-");
            if (st != ST_OPEN && st != ST_AUTH) {
                vr_emit("invariant", "auth_without_open", state_name(st));
            }
            transit(&st, ST_AUTH);
        } else if (op == 'D') {
            if (i >= n) {
                vr_emit("reject", "short_data", "-");
                break;
            }
            i += 1;
            vr_emit("op", "data", "-");
            if (st != ST_AUTH && st != ST_DATA) {
                vr_emit("invariant", "data_before_auth", state_name(st));
            }
            transit(&st, ST_DATA);
        } else if (op == 'C') {
            vr_emit("op", "close", "-");
            transit(&st, ST_CLOSED);
        } else if (op == 'N') {
            if (i >= n) {
                vr_emit("reject", "short_note", "-");
                break;
            }
            uint8_t b = data[i++];
            vr_emit("op", "note", "-");
            vr_emit("semantic", "note", note_label(b));
        } else if (op == 'L') {
            (void)consume_length(data, n, &i);
            if (i > n) {
                break;
            }
        } else if (op == 'S') {
            consume_scale(data, n, &i);
        } else {
            vr_emit("reject", "opcode", "unknown");
        }
    }
    vr_emit("semantic", "end_state", state_name(st));
    return 0;
}

int vr_target_execute(const uint8_t *data, size_t n) {
    if (n > VR_ABSOLUTE_INPUT_CAP) {
        vr_emit("reject", "too_large", "-");
        return -1;
    }
    if (n == 0 || data == NULL) {
        vr_emit("reject", "empty", "-");
        return 0;
    }
    uint8_t *copy = (uint8_t *)malloc(n);
    if (!copy) {
        vr_emit("reject", "alloc", "-");
        return -1;
    }
    memcpy(copy, data, n);
    int rc = parse_packet(copy, n);
    free(copy);
    return rc;
}
