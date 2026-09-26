#include "vr_target.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Isolation fixture. Not a demo vulnerability.
   FLOOD writes a large stderr. HANG loops until the parent deadline.
   ABORT raises SIGABRT. NOTE mirrors the semantic-label pattern. */

const char *vr_target_id(void) { return "hostile"; }
const char *vr_target_version(void) { return "fixture-1"; }

static int starts(const uint8_t *data, size_t n, const char *lit) {
    size_t k = strlen(lit);
    return n >= k && memcmp(data, lit, k) == 0;
}

int vr_target_execute(const uint8_t *data, size_t n) {
    if (starts(data, n, "FLOOD")) {
        char buf[1024];
        memset(buf, 'A', sizeof buf);
        buf[sizeof buf - 1] = '\n';
        for (int i = 0; i < 5000; i++) {
            fwrite(buf, 1, sizeof buf, stderr);
        }
        fflush(stderr);
        vr_emit("op", "flood", "-");
        return 0;
    }
    if (starts(data, n, "HANG")) {
        for (;;) {
            volatile unsigned x = 0;
            x++;
        }
    }
    if (starts(data, n, "ABORT")) {
        abort();
    }
    if (starts(data, n, "NOTE") && n >= 5) {
        static const char *labels[8] = {"alpha", "beta", "gamma", "delta",
                                         "epsilon", "zeta", "eta", "theta"};
        vr_emit("semantic", "note", labels[data[4] & 7]);
        return 0;
    }
    vr_emit("reject", "idle", "-");
    return 0;
}
