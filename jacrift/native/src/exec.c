#define _GNU_SOURCE

#include "exec.h"

#include "mutate.h"
#include "sha256.h"
#include "vr_target.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    uint32_t magic;
    uint32_t event_count;
    uint32_t completed;
    uint32_t truncated;
    char kind[VR_MAX_EVENTS][VR_FIELD];
    char a[VR_MAX_EVENTS][VR_FIELD];
    char b[VR_MAX_EVENTS][VR_FIELD];
} VrTrace;

static uint32_t g_guards;
static uint8_t *g_hits;
static uint8_t *g_seen;
static uint32_t *g_edge_count;
static VrTrace *g_trace;
static uint32_t g_edges_seen;
static uint32_t g_behavior_keys;

#define VR_KEY_CAP 8192
typedef struct {
    uint64_t key;
    uint32_t count;
    int used;
} VrKeySlot;
static VrKeySlot g_keys[VR_KEY_CAP];

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    if (start == stop || *start) {
        return;
    }
    for (uint32_t *x = start; x < stop; x++) {
        if (g_guards + 1 >= VR_EDGE_CAP) {
            *x = 0;
            continue;
        }
        *x = ++g_guards;
    }
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    uint32_t g = *guard;
    if (!g_hits || g == 0 || g >= VR_EDGE_CAP) {
        return;
    }
    if (g_hits[g] < 255) {
        g_hits[g]++;
    }
}

static int field_char(unsigned char c) {
    if (c >= 'a' && c <= 'z') return 1;
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= '0' && c <= '9') return 1;
    return c == '_' || c == '-' || c == '.' || c == ':' || c == '+';
}

static void copy_field(char *dst, const char *src) {
    size_t j = 0;
    if (!src) {
        src = "-";
    }
    for (size_t i = 0; src[i] && j + 1 < VR_FIELD; i++) {
        unsigned char c = (unsigned char)src[i];
        /* Drop ANSI introducers and other controls before they reach JSON. */
        if (c == 0x1b || c == 0x9b || c < 0x20 || c == 0x7f) {
            continue;
        }
        dst[j++] = field_char(c) ? (char)c : '_';
    }
    if (j == 0) {
        dst[0] = '-';
        dst[1] = 0;
        return;
    }
    dst[j] = 0;
}

void vr_emit(const char *kind, const char *a, const char *b) {
    if (!g_trace) {
        return;
    }
    if (g_trace->event_count >= VR_MAX_EVENTS) {
        g_trace->truncated++;
        return;
    }
    uint32_t i = g_trace->event_count++;
    copy_field(g_trace->kind[i], kind);
    copy_field(g_trace->a[i], a);
    copy_field(g_trace->b[i], b);
}

static uint64_t fnv(const char *s) {
    uint64_t h = 14695981039346656037ULL;
    if (!s) {
        return h;
    }
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h ^= *p;
        h *= 1099511628211ULL;
    }
    return h;
}

static uint64_t event_key(const char *kind, const char *a, const char *b) {
    char buf[VR_FIELD * 3 + 4];
    snprintf(buf, sizeof buf, "%s:%s:%s", kind ? kind : "-", a ? a : "-", b ? b : "-");
    return fnv(buf);
}

static int key_observe(uint64_t key, int commit, uint32_t *prior) {
    uint32_t slot = (uint32_t)(key % VR_KEY_CAP);
    for (uint32_t n = 0; n < VR_KEY_CAP; n++) {
        uint32_t i = (slot + n) % VR_KEY_CAP;
        if (!g_keys[i].used) {
            if (prior) *prior = 0;
            if (commit) {
                g_keys[i].used = 1;
                g_keys[i].key = key;
                g_keys[i].count = 1;
                g_behavior_keys++;
            }
            return 1;
        }
        if (g_keys[i].key == key) {
            if (prior) *prior = g_keys[i].count;
            if (commit && g_keys[i].count < 1000000u) {
                g_keys[i].count++;
            }
            return 0;
        }
    }
    if (prior) *prior = 0;
    return 0;
}

static uint64_t fingerprint_of(const VrTrace *tr) {
    uint64_t h = 14695981039346656037ULL;
    uint32_t n = tr->event_count;
    if (n > VR_MAX_EVENTS) n = VR_MAX_EVENTS;
    for (uint32_t i = 0; i < n; i++) {
        const char *parts[] = {tr->kind[i], tr->a[i], tr->b[i]};
        for (int p = 0; p < 3; p++) {
            for (const unsigned char *s = (const unsigned char *)parts[p]; *s; s++) {
                h ^= *s;
                h *= 1099511628211ULL;
            }
            h ^= (unsigned char)'|';
            h *= 1099511628211ULL;
        }
        h ^= (unsigned char)'\n';
        h *= 1099511628211ULL;
    }
    return h;
}

int vr_engine_init(void) {
    if (g_hits) {
        return 0;
    }
    size_t bytes = VR_EDGE_CAP;
    g_hits = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    g_trace = mmap(NULL, sizeof(VrTrace), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    g_seen = calloc(VR_EDGE_CAP, 1);
    g_edge_count = calloc(VR_EDGE_CAP, sizeof(uint32_t));
    if (g_hits == MAP_FAILED || g_trace == MAP_FAILED || !g_seen || !g_edge_count) {
        return -1;
    }
    memset(g_hits, 0, bytes);
    memset(g_trace, 0, sizeof(VrTrace));
    g_trace->magic = 0x56524631u;
    return 0;
}

void vr_engine_shutdown(void) {}

uint32_t vr_engine_guards(void) { return g_guards; }
uint32_t vr_engine_edges_seen(void) { return g_edges_seen; }
uint32_t vr_engine_behavior_keys(void) { return g_behavior_keys; }

const char *vr_exit_name(int exit_type) {
    switch (exit_type) {
    case VR_EXIT_NORMAL: return "NORMAL";
    case VR_EXIT_CRASH: return "CRASH";
    case VR_EXIT_TIMEOUT: return "TIMEOUT";
    case VR_EXIT_SANITIZER: return "SANITIZER";
    default: return "ENGINE";
    }
}

const char *vr_sanitizer_name(int sanitizer) {
    switch (sanitizer) {
    case VR_SAN_ADDRESS: return "address";
    case VR_SAN_UNDEFINED: return "undefined";
    case VR_SAN_OTHER: return "other";
    default: return "";
    }
}

static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static void strip_ansi(const char *in, char *out, size_t out_cap) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 1 < out_cap; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == 0x1b && in[i + 1] == '[') {
            i += 2;
            while (in[i] && !((unsigned char)in[i] >= 0x40 && (unsigned char)in[i] <= 0x7e)) {
                i++;
            }
            continue;
        }
        if (c < 0x09 || (c > 0x0d && c < 0x20) || c == 0x7f) {
            continue;
        }
        out[j++] = (char)c;
    }
    out[j] = 0;
}

static int copy_token(const char *in, char *out, size_t out_cap) {
    size_t n = 0;
    while (in[n] && in[n] != ' ' && in[n] != '\n' && in[n] != '(' && in[n] != '+' && n + 1 < out_cap) {
        out[n] = in[n];
        n++;
    }
    out[n] = 0;
    if (n == 0 || strstr(out, "Sanitizer") || strncmp(out, "vr_", 3) == 0 || strncmp(out, "__", 2) == 0) {
        out[0] = 0;
        return 0;
    }
    return 1;
}

/* Stack frames come only from lines that start with '#'. Prose such as
   "cannot be represented in type 'int'" must not become a function name.
   If UBSan prints no stack, the frame is the source location on that line. */
static void classify_stderr(const char *text, int *san, char *frame, size_t frame_cap) {
    *san = VR_SAN_NONE;
    if (frame_cap) frame[0] = 0;
    const char *line = text ? text : "";
    while (*line) {
        const char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        char buf[768];
        if (len >= sizeof buf) len = sizeof buf - 1;
        memcpy(buf, line, len);
        buf[len] = 0;
        if (strstr(buf, "AddressSanitizer")) {
            *san = VR_SAN_ADDRESS;
        } else if (*san != VR_SAN_ADDRESS &&
                   (strstr(buf, "UndefinedBehaviorSanitizer") || strstr(buf, "runtime error:"))) {
            *san = VR_SAN_UNDEFINED;
        } else if (*san == VR_SAN_NONE && strstr(buf, "Sanitizer")) {
            *san = VR_SAN_OTHER;
        }
        const char *s = buf;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '#') {
            const char *in = strstr(s, " in ");
            if (in && frame[0] == 0) {
                char tmp[VR_FRAME_LEN];
                if (copy_token(in + 4, tmp, sizeof tmp)) {
                    snprintf(frame, frame_cap, "%s", tmp);
                }
            }
        } else if (frame[0] == 0 && strstr(buf, "runtime error:")) {
            const char *mark = strstr(buf, ".c:");
            if (!mark) mark = strstr(buf, ".h:");
            if (mark) {
                const char *base = mark;
                while (base > buf && base[-1] != '/' && base[-1] != ' ') base--;
                char tmp[VR_FRAME_LEN];
                size_t n = 0;
                while (base < mark && n + 1 < sizeof tmp) tmp[n++] = *base++;
                tmp[n++] = ':';
                const char *digits = mark + 3;
                while (*digits >= '0' && *digits <= '9' && n + 1 < sizeof tmp) tmp[n++] = *digits++;
                tmp[n] = 0;
                snprintf(frame, frame_cap, "%s", tmp);
            }
        }
        if (!nl) break;
        line = nl + 1;
    }
}

static void child_limits(int timeout_ms) {
    struct rlimit rl;
    rl.rlim_cur = rl.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rl);
    unsigned sec = (unsigned)((timeout_ms / 1000) + 1);
    if (sec < 1) sec = 1;
    if (sec > 5) sec = 5;
    rl.rlim_cur = rl.rlim_max = sec;
    setrlimit(RLIMIT_CPU, &rl);
    rl.rlim_cur = rl.rlim_max = 1024 * 1024;
    setrlimit(RLIMIT_FSIZE, &rl);
    /* ASan reserves a huge virtual map, so RLIMIT_AS is intentionally unset.
       RLIMIT_NPROC is left alone: ASan may need helper threads. */
    alarm(sec + 1);
}

int vr_execute(const uint8_t *data, size_t n, int timeout_ms, int update_maps, VrExecOut *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    out->guards = g_guards;
    if (!g_hits || !g_trace) {
        out->exit_type = VR_EXIT_ENGINE;
        snprintf(out->frame, sizeof out->frame, "engine_uninitialized");
        return -1;
    }
    if (n > VR_ABSOLUTE_INPUT_CAP) {
        out->exit_type = VR_EXIT_ENGINE;
        snprintf(out->frame, sizeof out->frame, "input_too_large");
        return -1;
    }
    if (timeout_ms < 10) timeout_ms = 10;
    if (timeout_ms > 5000) timeout_ms = 5000;

    memset(g_hits, 0, VR_EDGE_CAP);
    memset(g_trace, 0, sizeof(VrTrace));
    g_trace->magic = 0x56524631u;

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        out->exit_type = VR_EXIT_ENGINE;
        snprintf(out->frame, sizeof out->frame, "pipe_failed");
        return -1;
    }
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    uint64_t t0 = now_us();
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        out->exit_type = VR_EXIT_ENGINE;
        snprintf(out->frame, sizeof out->frame, "fork_failed");
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        if (pipefd[1] > 2) close(pipefd[1]);
#ifdef __linux__
        closefrom(3);
#endif
        child_limits(timeout_ms);
        vr_target_execute(data, n);
        if (g_trace) g_trace->completed = 1;
        _exit(0);
    }
    close(pipefd[1]);

    char *errbuf = calloc(1, VR_STDERR_CAP + 1);
    size_t errlen = 0;
    int timed_out = 0;
    int status = 0;
    int reaped = 0;
    uint64_t deadline = t0 + (uint64_t)timeout_ms * 1000ULL;
    while (!reaped) {
        struct pollfd pfd;
        pfd.fd = pipefd[0];
        pfd.events = POLLIN;
        poll(&pfd, 1, 20);
        for (;;) {
            char tmp[4096];
            ssize_t r = read(pipefd[0], tmp, sizeof tmp);
            if (r > 0) {
                size_t take = (size_t)r;
                if (errlen < VR_STDERR_CAP) {
                    size_t room = VR_STDERR_CAP - errlen;
                    size_t copy = take < room ? take : room;
                    memcpy(errbuf + errlen, tmp, copy);
                    errlen += copy;
                }
                if ((size_t)r > 0 && errlen >= VR_STDERR_CAP) {
                    out->stderr_truncated = 1;
                }
                continue;
            }
            break;
        }
        pid_t wr = waitpid(pid, &status, WNOHANG);
        if (wr == pid) {
            reaped = 1;
            break;
        }
        if (now_us() > deadline) {
            timed_out = 1;
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            reaped = 1;
            break;
        }
    }
    /* Drain anything left so a writer is not stuck, then close. */
    for (;;) {
        char tmp[4096];
        ssize_t r = read(pipefd[0], tmp, sizeof tmp);
        if (r > 0) {
            if (errlen >= VR_STDERR_CAP) out->stderr_truncated = 1;
            else {
                size_t room = VR_STDERR_CAP - errlen;
                size_t copy = (size_t)r < room ? (size_t)r : room;
                memcpy(errbuf + errlen, tmp, copy);
                errlen += copy;
                if ((size_t)r > copy) out->stderr_truncated = 1;
            }
            continue;
        }
        break;
    }
    close(pipefd[0]);
    if (errbuf) errbuf[errlen] = 0;
    out->execution_us = now_us() - t0;

    int san = VR_SAN_NONE;
    classify_stderr(errbuf ? errbuf : "", &san, out->frame, sizeof out->frame);
    strip_ansi(errbuf ? errbuf : "", out->stderr_excerpt, sizeof out->stderr_excerpt);
    free(errbuf);
    out->sanitizer = san;
    out->completed = (int)g_trace->completed;
    out->events_truncated = (int)g_trace->truncated;
    out->event_count = g_trace->event_count;
    if (out->event_count > VR_MAX_EVENTS) out->event_count = VR_MAX_EVENTS;
    for (uint32_t i = 0; i < out->event_count; i++) {
        memcpy(out->events[i].kind, g_trace->kind[i], VR_FIELD);
        memcpy(out->events[i].a, g_trace->a[i], VR_FIELD);
        memcpy(out->events[i].b, g_trace->b[i], VR_FIELD);
    }
    out->fingerprint = fingerprint_of(g_trace);

    uint32_t neu = 0;
    uint32_t hit = 0;
    for (uint32_t g = 1; g <= g_guards && g < VR_EDGE_CAP; g++) {
        if (!g_hits[g]) continue;
        hit++;
        if (!g_seen[g]) {
            neu++;
            if (update_maps) {
                g_seen[g] = 1;
                g_edges_seen++;
            }
        }
        if (update_maps && g_edge_count[g] < 1000000u) {
            g_edge_count[g]++;
        }
    }
    out->new_edges = neu;
    out->hit_edges = hit;
    out->edges_seen_total = update_maps ? g_edges_seen : g_edges_seen + neu;

    uint32_t bnew = 0;
    for (uint32_t i = 0; i < out->event_count; i++) {
        const char *k = out->events[i].kind;
        int tracked = strcmp(k, "transition") == 0 || strcmp(k, "semantic") == 0 ||
                      strcmp(k, "invariant") == 0 || strcmp(k, "op") == 0;
        if (!tracked) continue;
        const char *b = strcmp(k, "op") == 0 ? "-" : out->events[i].b;
        uint64_t key = event_key(k, out->events[i].a, b);
        uint32_t prior = 0;
        int is_new = key_observe(key, update_maps, &prior);
        if (is_new) bnew++;
    }
    out->behavior_new = bnew;

    if (timed_out) {
        out->exit_type = VR_EXIT_TIMEOUT;
        out->signal_num = SIGKILL;
        return 0;
    }
    if (WIFSIGNALED(status)) {
        out->signal_num = WTERMSIG(status);
        out->exit_type = san != VR_SAN_NONE ? VR_EXIT_SANITIZER : VR_EXIT_CRASH;
        return 0;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        out->signal_num = 0;
        out->exit_type = san != VR_SAN_NONE ? VR_EXIT_SANITIZER : VR_EXIT_CRASH;
        return 0;
    }
    if (san != VR_SAN_NONE) {
        out->exit_type = VR_EXIT_SANITIZER;
        return 0;
    }
    out->exit_type = VR_EXIT_NORMAL;
    return 0;
}

int vr_engine_self_test(void) {
    uint8_t dig[32];
    vr_sha256((const uint8_t *)"abc", 3, dig);
    static const uint8_t abc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    if (memcmp(dig, abc, 32) != 0) {
        fprintf(stderr, "sha256 self-test failed\n");
        return 1;
    }
    VrRng rng;
    vr_rng_seed(&rng, 1);
    uint8_t in[4] = {1, 2, 3, 4};
    uint8_t a[16], b[16];
    char op[32];
    VrRng r2 = rng;
    size_t na = vr_mutate(&rng, in, 4, a, sizeof a, NULL, 0, op, sizeof op);
    size_t nb = vr_mutate(&r2, in, 4, b, sizeof b, NULL, 0, op, sizeof op);
    if (na == 0 || na != nb || memcmp(a, b, na) != 0) {
        fprintf(stderr, "mutate determinism failed\n");
        return 1;
    }
    char nasty[VR_FIELD];
    /* copy_field is exercised through vr_emit during a real execute */
    (void)nasty;
    if (vr_engine_init() != 0) {
        fprintf(stderr, "engine init failed\n");
        return 1;
    }
    const uint8_t sample[] = {'V', 'R', 'N', 0x00};
    const uint8_t *first = sample;
    size_t first_n = sizeof sample;
    int expect_behavior_split = strcmp(vr_target_id(), "riftpacket") == 0;
    if (!expect_behavior_split) {
        static const uint8_t idle[] = {'I', 'D', 'L', 'E'};
        first = idle;
        first_n = sizeof idle;
    }
    VrExecOut out;
    if (vr_execute(first, first_n, 500, 1, &out) != 0) {
        fprintf(stderr, "execute failed\n");
        return 1;
    }
    if (out.exit_type != VR_EXIT_NORMAL) {
        fprintf(stderr, "expected normal exit, got %s\n", vr_exit_name(out.exit_type));
        return 1;
    }
    if (out.new_edges == 0 || out.guards == 0) {
        fprintf(stderr, "expected instrumented edges, guards=%u new=%u\n", out.guards, out.new_edges);
        return 1;
    }
    VrExecOut again;
    if (vr_execute(first, first_n, 500, 1, &again) != 0) return 1;
    if (again.new_edges != 0) {
        fprintf(stderr, "repeat input reported new edges %u\n", again.new_edges);
        return 1;
    }
    if (expect_behavior_split) {
        const uint8_t other[] = {'V', 'R', 'N', 0x01};
        VrExecOut note;
        if (vr_execute(other, sizeof other, 500, 1, &note) != 0) return 1;
        if (note.new_edges != 0) {
            fprintf(stderr, "semantic sibling changed coverage (%u)\n", note.new_edges);
            return 1;
        }
        if (note.behavior_new == 0) {
            fprintf(stderr, "semantic sibling was not behavior-novel\n");
            return 1;
        }
    }
    fprintf(stdout, "self-test ok guards=%u edges=%u behavior_keys=%u\n", vr_engine_guards(),
            vr_engine_edges_seen(), vr_engine_behavior_keys());
    return 0;
}
