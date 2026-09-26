#ifndef VR_EXEC_H
#define VR_EXEC_H

#include <stddef.h>
#include <stdint.h>

#define VR_MAX_EVENTS 48
#define VR_FIELD 48
#define VR_EDGE_CAP 65536
#define VR_STDERR_CAP 65536
#define VR_FRAME_LEN 96

enum VrExitType {
    VR_EXIT_NORMAL = 0,
    VR_EXIT_CRASH = 1,
    VR_EXIT_TIMEOUT = 2,
    VR_EXIT_SANITIZER = 3,
    VR_EXIT_ENGINE = 4
};

enum VrSanitizer {
    VR_SAN_NONE = 0,
    VR_SAN_ADDRESS = 1,
    VR_SAN_UNDEFINED = 2,
    VR_SAN_OTHER = 3
};

typedef struct {
    char kind[VR_FIELD];
    char a[VR_FIELD];
    char b[VR_FIELD];
} VrEvent;

typedef struct {
    int exit_type;
    int sanitizer;
    int signal_num;
    int completed;
    int stderr_truncated;
    int events_truncated;
    uint32_t new_edges;
    uint32_t hit_edges;
    uint32_t edges_seen_total;
    uint32_t guards;
    uint32_t behavior_new;
    uint32_t event_count;
    uint64_t fingerprint;
    uint64_t execution_us;
    char frame[VR_FRAME_LEN];
    char stderr_excerpt[2048];
    VrEvent events[VR_MAX_EVENTS];
} VrExecOut;

int vr_engine_init(void);
void vr_engine_shutdown(void);
uint32_t vr_engine_guards(void);
uint32_t vr_engine_edges_seen(void);
uint32_t vr_engine_behavior_keys(void);

/* Runs the linked target once in a forked child.
   update_maps=1 commits coverage and behavior keys into the campaign maps. */
int vr_execute(const uint8_t *data, size_t n, int timeout_ms, int update_maps, VrExecOut *out);

const char *vr_exit_name(int exit_type);
const char *vr_sanitizer_name(int sanitizer);

/* 0 on success. Used by --self-test. */
int vr_engine_self_test(void);

#endif
