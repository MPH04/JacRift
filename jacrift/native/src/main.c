#include "campaign.h"
#include "exec.h"
#include "vr_target.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void set_sanitizer_env(void) {
    const char *sym = "/usr/lib/llvm-18/bin/llvm-symbolizer";
    if (access(sym, X_OK) != 0) {
        sym = "llvm-symbolizer";
    }
    setenv("ASAN_SYMBOLIZER_PATH", sym, 0);
    setenv("UBSAN_SYMBOLIZER_PATH", sym, 0);
    setenv("ASAN_OPTIONS",
           "abort_on_error=1:halt_on_error=1:detect_leaks=0:symbolize=1:allocator_may_return_null=1", 0);
    setenv("UBSAN_OPTIONS", "abort_on_error=1:halt_on_error=1:print_stacktrace=1:symbolize=1", 0);
    /* Children inherit these. VectorRift does not phone home. */
    setenv("ASAN_OPTIONS",
           "abort_on_error=1:halt_on_error=1:detect_leaks=0:symbolize=1:allocator_may_return_null=1", 0);
}

static void print_version(void) {
    printf("vectorrift-fuzzer\n");
    printf("target_id=%s\n", vr_target_id());
    printf("target_version=%s\n", vr_target_version());
    printf("compiler=clang-%d.%d\n", __clang_major__, __clang_minor__);
    printf("coverage=trace-pc-guard\n");
    printf("sanitizers=address,undefined\n");
    printf("flags=-fsanitize=address,undefined -fsanitize-coverage=trace-pc-guard "
           "-fno-sanitize-recover=all -O1 -g\n");
}

int main(int argc, char **argv) {
    set_sanitizer_env();
    if (argc < 2) {
        fprintf(stderr, "usage: %s version|self-test|run|replay|minimize [flags]\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "version") == 0) {
        print_version();
        return 0;
    }
    if (strcmp(argv[1], "self-test") == 0) {
        return vr_engine_self_test();
    }
    if (strcmp(argv[1], "run") == 0) return vr_cmd_run(argc - 2, argv + 2);
    if (strcmp(argv[1], "replay") == 0) return vr_cmd_replay(argc - 2, argv + 2);
    if (strcmp(argv[1], "minimize") == 0) return vr_cmd_minimize(argc - 2, argv + 2);
    if (strcmp(argv[1], "compare") == 0) return vr_cmd_compare(argc - 2, argv + 2);
    fprintf(stderr, "unknown command %s\n", argv[1]);
    return 2;
}
