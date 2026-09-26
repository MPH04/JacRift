#include "mutate.h"

#include "vr_target.h"

#include <string.h>

void vr_rng_seed(VrRng *rng, uint64_t seed) {
    rng->s = seed ? seed : 0x56454354ULL; /* "VECT" */
}

uint64_t vr_rng_next(VrRng *rng) {
    uint64_t z = (rng->s += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

uint32_t vr_rng_below(VrRng *rng, uint32_t n) {
    if (n == 0) {
        return 0;
    }
    return (uint32_t)(vr_rng_next(rng) % n);
}

static void set_op(char *op_name, size_t op_cap, const char *name) {
    if (!op_name || op_cap == 0) {
        return;
    }
    size_t i = 0;
    for (; name[i] && i + 1 < op_cap; i++) {
        op_name[i] = name[i];
    }
    op_name[i] = 0;
}

static size_t clamp_copy(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap) {
    size_t n = in_len;
    if (n > out_cap) {
        n = out_cap;
    }
    if (n > VR_MAX_MUTATION_INPUT) {
        n = VR_MAX_MUTATION_INPUT;
    }
    if (n && in) {
        memcpy(out, in, n);
    }
    return n;
}

size_t vr_mutate(VrRng *rng, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap,
                 const uint8_t *splice, size_t splice_len, char *op_name, size_t op_cap) {
    static const uint8_t k8[] = {0, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255};
    static const uint16_t k16[] = {0, 1, 128, 255, 256, 512, 1024, 4096, 0x7fff, 0x8000, 0xffff};
    static const uint32_t k32[] = {0, 1, 100000u, 46341u, 0x7fffffffu, 0x80000000u, 0xffffffffu};

    if (!out || out_cap == 0) {
        set_op(op_name, op_cap, "empty");
        return 0;
    }
    size_t cap = out_cap;
    if (cap > VR_MAX_MUTATION_INPUT) {
        cap = VR_MAX_MUTATION_INPUT;
    }
    size_t n = clamp_copy(in, in_len, out, cap);
    uint32_t roll = vr_rng_below(rng, 9);

    if (n == 0 || roll == 5) {
        /* insert */
        if (n >= cap) {
            set_op(op_name, op_cap, "byte");
            if (n == 0) {
                return 0;
            }
            out[vr_rng_below(rng, (uint32_t)n)] = (uint8_t)vr_rng_below(rng, 256);
            return n;
        }
        size_t at = n == 0 ? 0 : vr_rng_below(rng, (uint32_t)(n + 1));
        memmove(out + at + 1, out + at, n - at);
        out[at] = (uint8_t)vr_rng_below(rng, 256);
        set_op(op_name, op_cap, "insert");
        return n + 1;
    }

    if (roll == 0) {
        size_t bit = vr_rng_below(rng, (uint32_t)(n * 8));
        out[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        set_op(op_name, op_cap, "bitflip");
        return n;
    }
    if (roll == 1) {
        out[vr_rng_below(rng, (uint32_t)n)] = (uint8_t)vr_rng_below(rng, 256);
        set_op(op_name, op_cap, "byte");
        return n;
    }
    if (roll == 2) {
        out[vr_rng_below(rng, (uint32_t)n)] = k8[vr_rng_below(rng, (uint32_t)(sizeof k8))];
        set_op(op_name, op_cap, "interest8");
        return n;
    }
    if (roll == 3 && n >= 2) {
        size_t at = vr_rng_below(rng, (uint32_t)(n - 1));
        uint16_t v = k16[vr_rng_below(rng, (uint32_t)(sizeof k16 / sizeof k16[0]))];
        out[at] = (uint8_t)(v >> 8);
        out[at + 1] = (uint8_t)(v & 0xff);
        set_op(op_name, op_cap, "interest16");
        return n;
    }
    if (roll == 4 && n >= 4) {
        size_t at = vr_rng_below(rng, (uint32_t)(n - 3));
        uint32_t v = k32[vr_rng_below(rng, (uint32_t)(sizeof k32 / sizeof k32[0]))];
        out[at] = (uint8_t)(v >> 24);
        out[at + 1] = (uint8_t)(v >> 16);
        out[at + 2] = (uint8_t)(v >> 8);
        out[at + 3] = (uint8_t)v;
        set_op(op_name, op_cap, "interest32");
        return n;
    }
    if (roll == 6 && n > 1) {
        size_t at = vr_rng_below(rng, (uint32_t)n);
        memmove(out + at, out + at + 1, n - at - 1);
        set_op(op_name, op_cap, "delete");
        return n - 1;
    }
    if (roll == 7 && splice && splice_len > 0 && n > 0) {
        size_t a = vr_rng_below(rng, (uint32_t)n);
        size_t b = vr_rng_below(rng, (uint32_t)splice_len);
        size_t take = splice_len - b;
        if (a + take > cap) {
            take = cap - a;
        }
        memcpy(out + a, splice + b, take);
        size_t out_n = a + take;
        if (out_n < n && vr_rng_below(rng, 2) == 0) {
            /* keep tail of original when it fits */
            size_t tail = n - a;
            if (out_n + tail > cap) {
                tail = cap - out_n;
            }
            memcpy(out + out_n, in + (in_len - tail), tail);
            out_n += tail;
        }
        set_op(op_name, op_cap, "splice");
        return out_n;
    }
    if (n > 0) {
        size_t at = vr_rng_below(rng, (uint32_t)n);
        size_t len = 1 + vr_rng_below(rng, (uint32_t)(n - at > 8 ? 8 : (n - at)));
        uint8_t fill = (uint8_t)vr_rng_below(rng, 256);
        memset(out + at, fill, len);
        set_op(op_name, op_cap, "overwrite");
        return n;
    }
    set_op(op_name, op_cap, "byte");
    return n;
}
