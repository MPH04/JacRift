#include "vr_target.h"

#include <stdint.h>
#include <stddef.h>

/* libFuzzer supplies its own SanitizerCoverage callbacks.
   Behavior events are discarded here; this binary exists to prove LLVM's
   coverage-guided loop can execute the same target function. VectorRift's
   investigation pipeline uses vrfuzz_* events, not libFuzzer's stdout. */

void vr_emit(const char *kind, const char *a, const char *b) {
    (void)kind;
    (void)a;
    (void)b;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    vr_target_execute(data, size);
    return 0;
}
