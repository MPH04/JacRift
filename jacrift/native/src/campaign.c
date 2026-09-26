#include "campaign.h"

#include "exec.h"
#include "mutate.h"
#include "sha256.h"
#include "vr_target.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define VR_CORPUS_MAX 192

typedef struct {
    uint8_t *data;
    size_t len;
    char id[17];
    char parent[17];
    char mutation[24];
    int favored;
} VrInput;

static void json_escape(FILE *fp, const char *s) {
    fputc('"', fp);
    if (!s) {
        fputc('"', fp);
        return;
    }
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        if (c == '"' || c == '\\') {
            fprintf(fp, "\\%c", c);
        } else if (c == '\n') {
            fputs("\\n", fp);
        } else if (c == '\r') {
            fputs("\\r", fp);
        } else if (c == '\t') {
            fputs("\\t", fp);
        } else if (c < 0x20) {
            fprintf(fp, "\\u%04x", c);
        } else {
            fputc(c, fp);
        }
    }
    fputc('"', fp);
}

static void hex_encode(const uint8_t *data, size_t n, char *out, size_t out_cap) {
    static const char hexd[] = "0123456789abcdef";
    size_t j = 0;
    for (size_t i = 0; i < n && j + 2 < out_cap; i++) {
        out[j++] = hexd[data[i] >> 4];
        out[j++] = hexd[data[i] & 0xf];
    }
    out[j] = 0;
}

static int ensure_dir(const char *path) {
    if (mkdir(path, 0700) == 0 || errno == EEXIST) {
        return 0;
    }
    return -1;
}

static void join2(char *dst, size_t cap, const char *a, const char *b) {
    snprintf(dst, cap, "%s/%s", a, b);
}

static int write_atomic(const char *path, const char *contents) {
    char tmp[1024];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *fp = fopen(tmp, "w");
    if (!fp) return -1;
    fputs(contents, fp);
    if (fclose(fp) != 0) return -1;
    if (rename(tmp, path) != 0) return -1;
    return 0;
}

static int read_file(const char *path, uint8_t **out, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long sz = ftell(fp);
    if (sz < 0 || sz > VR_ABSOLUTE_INPUT_CAP) {
        fclose(fp);
        return -1;
    }
    rewind(fp);
    uint8_t *buf = sz ? malloc((size_t)sz) : malloc(1);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    if (sz && fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    *out = buf;
    *out_len = (size_t)sz;
    return 0;
}

static void id_of(const uint8_t *data, size_t n, char out[17]) {
    char hex[65];
    vr_sha256_hex(data, n, hex);
    memcpy(out, hex, 16);
    out[16] = 0;
}

static int save_blob(const char *dir, const char *id, const uint8_t *data, size_t n) {
    char path[768];
    snprintf(path, sizeof path, "%s/%s.bin", dir, id);
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    if (n && fwrite(data, 1, n, fp) != n) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static void write_event(FILE *fp, const char *input_id, const char *parent, const char *mutation,
                        uint64_t seed, uint32_t index, const uint8_t *data, size_t n,
                        const VrExecOut *ex, int saved) {
    char hex[256];
    size_t show = n > 96 ? 96 : n;
    hex_encode(data, show, hex, sizeof hex);
    char fphex[17];
    snprintf(fphex, sizeof fphex, "%016llx", (unsigned long long)ex->fingerprint);
    fprintf(fp, "{\"schema\":\"vectorrift.execution.v1\",\"input_id\":");
    json_escape(fp, input_id);
    fprintf(fp, ",\"parent_id\":");
    json_escape(fp, parent && parent[0] ? parent : "");
    fprintf(fp, ",\"mutation\":");
    json_escape(fp, mutation ? mutation : "");
    fprintf(fp,
            ",\"seed\":%llu,\"exec_index\":%u,\"input_len\":%zu,\"input_hex\":",
            (unsigned long long)seed, index, n);
    json_escape(fp, hex);
    fprintf(fp, ",\"input_hex_truncated\":%s,\"saved\":%s,\"exit_type\":", n > 96 ? "true" : "false",
            saved ? "true" : "false");
    json_escape(fp, vr_exit_name(ex->exit_type));
    fprintf(fp, ",\"sanitizer\":");
    json_escape(fp, vr_sanitizer_name(ex->sanitizer));
    fprintf(fp,
            ",\"signal\":%d,\"new_edges\":%u,\"hit_edges\":%u,\"edges_seen_total\":%u,\"guards\":%u,"
            "\"behavior_new\":%u,\"fingerprint\":\"%s\",\"execution_us\":%llu,\"completed\":%s,"
            "\"stderr_truncated\":%s,\"events_truncated\":%s,\"frame\":",
            ex->signal_num, ex->new_edges, ex->hit_edges, ex->edges_seen_total, ex->guards, ex->behavior_new,
            fphex, (unsigned long long)ex->execution_us, ex->completed ? "true" : "false",
            ex->stderr_truncated ? "true" : "false", ex->events_truncated ? "true" : "false");
    json_escape(fp, ex->frame);
    fprintf(fp, ",\"stderr_excerpt\":");
    json_escape(fp, ex->stderr_excerpt);
    fputs(",\"events\":[", fp);
    for (uint32_t i = 0; i < ex->event_count; i++) {
        if (i) fputc(',', fp);
        fputs("{\"kind\":", fp);
        json_escape(fp, ex->events[i].kind);
        fputs(",\"a\":", fp);
        json_escape(fp, ex->events[i].a);
        fputs(",\"b\":", fp);
        json_escape(fp, ex->events[i].b);
        fputc('}', fp);
    }
    fputs("]}\n", fp);
}

static const char *flag_arg(int argc, char **argv, const char *name, const char *fallback) {
    for (int i = 0; i < argc - 1; i++) {
        if (strcmp(argv[i], name) == 0) return argv[i + 1];
    }
    return fallback;
}

static long num_arg(int argc, char **argv, const char *name, long fallback) {
    const char *v = flag_arg(argc, argv, name, NULL);
    if (!v) return fallback;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    if (!end || *end) return fallback;
    return n;
}

static int load_seeds(const char *dir, VrInput *items, int cap, int *count) {
    *count = 0;
    DIR *d = opendir(dir);
    if (!d) return -1;
    char names[256][256];
    int nnames = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && nnames < 256) {
        if (de->d_name[0] == '.') continue;
        size_t L = strlen(de->d_name);
        if (L < 4 || strcmp(de->d_name + L - 4, ".bin") != 0) continue;
        snprintf(names[nnames], sizeof names[nnames], "%s", de->d_name);
        nnames++;
    }
    closedir(d);
    /* insertion sort for determinism */
    for (int i = 1; i < nnames; i++) {
        char key[256];
        snprintf(key, sizeof key, "%s", names[i]);
        int j = i - 1;
        while (j >= 0 && strcmp(names[j], key) > 0) {
            snprintf(names[j + 1], sizeof names[j + 1], "%s", names[j]);
            j--;
        }
        snprintf(names[j + 1], sizeof names[j + 1], "%s", key);
    }
    for (int i = 0; i < nnames && *count < cap; i++) {
        char path[768];
        snprintf(path, sizeof path, "%s/%s", dir, names[i]);
        struct stat st;
        if (lstat(path, &st) != 0) continue;
        if (!S_ISREG(st.st_mode)) continue;
        if (st.st_size > VR_MAX_MUTATION_INPUT) continue;
        uint8_t *buf = NULL;
        size_t len = 0;
        if (read_file(path, &buf, &len) != 0) continue;
        items[*count].data = buf;
        items[*count].len = len;
        id_of(buf, len, items[*count].id);
        items[*count].parent[0] = 0;
        snprintf(items[*count].mutation, sizeof items[*count].mutation, "seed");
        items[*count].favored = 0;
        (*count)++;
    }
    return 0;
}

static int corpus_has(VrInput *items, int count, const char *id) {
    for (int i = 0; i < count; i++) {
        if (strcmp(items[i].id, id) == 0) return 1;
    }
    return 0;
}

static int add_corpus(VrInput *items, int *count, const uint8_t *data, size_t len, const char *parent,
                      const char *mutation, int favored) {
    if (*count >= VR_CORPUS_MAX) return 0;
    char id[17];
    id_of(data, len, id);
    if (corpus_has(items, *count, id)) return 0;
    uint8_t *copy = malloc(len ? len : 1);
    if (!copy) return 0;
    if (len) memcpy(copy, data, len);
    items[*count].data = copy;
    items[*count].len = len;
    memcpy(items[*count].id, id, 17);
    snprintf(items[*count].parent, sizeof items[*count].parent, "%s", parent ? parent : "");
    snprintf(items[*count].mutation, sizeof items[*count].mutation, "%s", mutation ? mutation : "");
    items[*count].favored = favored;
    (*count)++;
    return 1;
}

static void write_progress(const char *path, uint32_t execs, uint32_t edges, uint32_t behavior,
                           uint32_t crashes, uint32_t sanitizers, uint32_t timeouts, uint32_t corpus,
                           uint64_t elapsed_ms, uint32_t guards) {
    char buf[1024];
    double rate = elapsed_ms > 0 ? (double)execs * 1000.0 / (double)elapsed_ms : 0;
    snprintf(buf, sizeof buf,
             "{\"schema\":\"vectorrift.progress.v1\",\"executions\":%u,\"edges_seen\":%u,"
             "\"behavior_keys\":%u,\"crashes\":%u,\"sanitizer_failures\":%u,\"timeouts\":%u,"
             "\"corpus_size\":%u,\"elapsed_ms\":%llu,\"execs_per_sec\":%.3f,\"guards\":%u,"
             "\"target_id\":\"%s\",\"target_version\":\"%s\"}\n",
             execs, edges, behavior, crashes, sanitizers, timeouts, corpus,
             (unsigned long long)elapsed_ms, rate, guards, vr_target_id(), vr_target_version());
    write_atomic(path, buf);
}

static void failure_signature(const VrExecOut *ex, char *out, size_t cap) {
    snprintf(out, cap, "%s|%s|%s", vr_exit_name(ex->exit_type), vr_sanitizer_name(ex->sanitizer), ex->frame);
}

int vr_cmd_replay(int argc, char **argv) {
    const char *input = flag_arg(argc, argv, "--input", NULL);
    long timeout = num_arg(argc, argv, "--timeout-ms", 500);
    if (!input) {
        fprintf(stderr, "replay requires --input\n");
        return 2;
    }
    uint8_t *buf = NULL;
    size_t len = 0;
    if (read_file(input, &buf, &len) != 0) {
        fprintf(stderr, "could not read input\n");
        return 2;
    }
    if (vr_engine_init() != 0) {
        free(buf);
        return 2;
    }
    VrExecOut ex;
    if (vr_execute(buf, len, (int)timeout, 0, &ex) != 0) {
        free(buf);
        return 2;
    }
    char id[17];
    id_of(buf, len, id);
    write_event(stdout, id, "", "replay", 0, 0, buf, len, &ex, 0);
    free(buf);
    return ex.exit_type == VR_EXIT_ENGINE ? 2 : 0;
}

static int failure_matches(const VrExecOut *ex, int san, const char *frame) {
    if (ex->exit_type != VR_EXIT_SANITIZER && ex->exit_type != VR_EXIT_CRASH) return 0;
    if (san != VR_SAN_NONE && ex->sanitizer != san) return 0;
    if (frame && frame[0] && ex->frame[0] && strcmp(ex->frame, frame) != 0) return 0;
    return 1;
}

int vr_cmd_minimize(int argc, char **argv) {
    const char *input = flag_arg(argc, argv, "--input", NULL);
    const char *out_path = flag_arg(argc, argv, "--out", NULL);
    long timeout = num_arg(argc, argv, "--timeout-ms", 500);
    if (!input || !out_path) {
        fprintf(stderr, "minimize requires --input and --out\n");
        return 2;
    }
    uint8_t *orig = NULL;
    size_t orig_n = 0;
    if (read_file(input, &orig, &orig_n) != 0) return 2;
    if (vr_engine_init() != 0) {
        free(orig);
        return 2;
    }
    VrExecOut base;
    if (vr_execute(orig, orig_n, (int)timeout, 0, &base) != 0) {
        free(orig);
        return 2;
    }
    if (!failure_matches(&base, base.sanitizer, base.frame)) {
        fprintf(stdout,
                "{\"schema\":\"vectorrift.minimize.v1\",\"ok\":false,\"reason\":\"input_did_not_fail\","
                "\"execs\":1}\n");
        free(orig);
        return 1;
    }
    uint8_t *cur = malloc(orig_n ? orig_n : 1);
    size_t cur_n = orig_n;
    if (orig_n) memcpy(cur, orig, orig_n);
    int execs = 1;
    size_t nparts = 2;
    int guard = 0;
    while (cur_n >= 2 && guard < 400) {
        int reduced = 0;
        if (nparts > cur_n) nparts = cur_n;
        size_t chunk = cur_n / nparts;
        if (chunk == 0) chunk = 1;
        for (size_t part = 0; part < nparts && guard < 400; part++) {
            size_t start = part * chunk;
            if (start >= cur_n) break;
            size_t end = (part == nparts - 1) ? cur_n : start + chunk;
            if (end > cur_n) end = cur_n;
            size_t drop = end - start;
            if (drop == 0 || drop == cur_n) continue;
            size_t trial_n = cur_n - drop;
            uint8_t *trial = malloc(trial_n ? trial_n : 1);
            memcpy(trial, cur, start);
            memcpy(trial + start, cur + end, cur_n - end);
            VrExecOut ex;
            vr_execute(trial, trial_n, (int)timeout, 0, &ex);
            execs++;
            guard++;
            if (failure_matches(&ex, base.sanitizer, base.frame)) {
                free(cur);
                cur = trial;
                cur_n = trial_n;
                if (nparts > 2) nparts--;
                reduced = 1;
                break;
            }
            free(trial);
        }
        if (!reduced) {
            if (nparts >= cur_n) break;
            size_t next = nparts * 2;
            nparts = next > cur_n ? cur_n : next;
        }
    }
    FILE *fp = fopen(out_path, "wb");
    if (!fp) {
        free(orig);
        free(cur);
        return 2;
    }
    if (cur_n) fwrite(cur, 1, cur_n, fp);
    fclose(fp);
    char id[17];
    id_of(cur, cur_n, id);
    fprintf(stdout,
            "{\"schema\":\"vectorrift.minimize.v1\",\"ok\":true,\"input_id\":\"%s\",\"original_len\":%zu,"
            "\"minimized_len\":%zu,\"execs\":%d,\"sanitizer\":\"%s\",\"frame\":",
            id, orig_n, cur_n, execs, vr_sanitizer_name(base.sanitizer));
    json_escape(stdout, base.frame);
    fprintf(stdout, ",\"incomplete\":%s}\n", guard >= 400 ? "true" : "false");
    free(orig);
    free(cur);
    return 0;
}

int vr_cmd_compare(int argc, char **argv) {
    const char *before = flag_arg(argc, argv, "--before", NULL);
    const char *input = flag_arg(argc, argv, "--input", NULL);
    long timeout = num_arg(argc, argv, "--timeout-ms", 500);
    if (!before || !input) {
        fprintf(stderr, "compare requires --before and --input\n");
        return 2;
    }
    uint8_t *a = NULL;
    uint8_t *b = NULL;
    size_t an = 0;
    size_t bn = 0;
    if (read_file(before, &a, &an) != 0 || read_file(input, &b, &bn) != 0) {
        free(a);
        free(b);
        fprintf(stderr, "could not read compare inputs\n");
        return 2;
    }
    if (vr_engine_init() != 0) {
        free(a);
        free(b);
        return 2;
    }
    VrExecOut ignored;
    if (vr_execute(a, an, (int)timeout, 1, &ignored) != 0) {
        free(a);
        free(b);
        return 2;
    }
    VrExecOut ex;
    if (vr_execute(b, bn, (int)timeout, 1, &ex) != 0) {
        free(a);
        free(b);
        return 2;
    }
    char id[17];
    id_of(b, bn, id);
    write_event(stdout, id, "", "compare", 0, 1, b, bn, &ex, 0);
    free(a);
    free(b);
    return 0;
}

int vr_cmd_run(int argc, char **argv) {
    const char *seeds = flag_arg(argc, argv, "--seeds", NULL);
    const char *out = flag_arg(argc, argv, "--out", NULL);
    long seed = num_arg(argc, argv, "--seed", 1);
    long exec_budget = num_arg(argc, argv, "--execs", 500);
    long timeout = num_arg(argc, argv, "--timeout-ms", 200);
    if (!seeds || !out) {
        fprintf(stderr, "run requires --seeds and --out\n");
        return 2;
    }
    if (exec_budget < 1) exec_budget = 1;
    if (exec_budget > 200000) exec_budget = 200000;
    if (ensure_dir(out) != 0) {
        fprintf(stderr, "cannot create output directory\n");
        return 2;
    }
    char corpus_dir[768], fail_dir[768], events_path[768], progress_path[768], summary_path[768];
    join2(corpus_dir, sizeof corpus_dir, out, "corpus");
    join2(fail_dir, sizeof fail_dir, out, "failures");
    join2(events_path, sizeof events_path, out, "events.jsonl");
    join2(progress_path, sizeof progress_path, out, "progress.json");
    join2(summary_path, sizeof summary_path, out, "summary.json");
    ensure_dir(corpus_dir);
    ensure_dir(fail_dir);

    /* Symbolizing every sanitizer hit dominates runtime and does not change
       which input failed. Replay and minimize symbolize; the campaign does not. */
    setenv("ASAN_OPTIONS",
           "abort_on_error=1:halt_on_error=1:detect_leaks=0:symbolize=0:allocator_may_return_null=1", 1);
    setenv("UBSAN_OPTIONS", "abort_on_error=1:halt_on_error=1:print_stacktrace=0:symbolize=0", 1);
    if (vr_engine_init() != 0) return 2;
    VrInput *items = calloc(VR_CORPUS_MAX, sizeof(VrInput));
    int count = 0;
    if (load_seeds(seeds, items, VR_CORPUS_MAX, &count) != 0 || count == 0) {
        fprintf(stderr, "no usable seeds in %s\n", seeds);
        free(items);
        return 2;
    }
    FILE *events = fopen(events_path, "w");
    if (!events) {
        free(items);
        return 2;
    }
    uint32_t execs = 0, crashes = 0, sanitizers = 0, timeouts = 0, skipped = 0;
    char seen_fail[64][160];
    int nfail = 0;
    uint64_t t0 = 0;
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        t0 = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
    }
    VrRng rng;
    vr_rng_seed(&rng, (uint64_t)seed);

    /* Execute seeds first so the baseline is measured before mutation. */
    for (int i = 0; i < count && execs < (uint32_t)exec_budget; i++) {
        VrExecOut ex;
        vr_execute(items[i].data, items[i].len, (int)timeout, 1, &ex);
        int novel = ex.new_edges || ex.behavior_new;
        int fail = ex.exit_type == VR_EXIT_CRASH || ex.exit_type == VR_EXIT_SANITIZER ||
                   ex.exit_type == VR_EXIT_TIMEOUT;
        char sig[160];
        failure_signature(&ex, sig, sizeof sig);
        int new_sig = 0;
        if (fail) {
            new_sig = 1;
            for (int s = 0; s < nfail; s++) {
                if (strcmp(seen_fail[s], sig) == 0) new_sig = 0;
            }
            if (new_sig && nfail < 64) {
                snprintf(seen_fail[nfail], sizeof seen_fail[nfail], "%s", sig);
                nfail++;
            }
        }
        int save = novel || new_sig;
        if (save) {
            save_blob(ex.exit_type == VR_EXIT_NORMAL ? corpus_dir : fail_dir, items[i].id, items[i].data,
                      items[i].len);
            if (novel) items[i].favored = 1;
        }
        if (ex.exit_type == VR_EXIT_CRASH) crashes++;
        if (ex.exit_type == VR_EXIT_SANITIZER) sanitizers++;
        if (ex.exit_type == VR_EXIT_TIMEOUT) timeouts++;
        write_event(events, items[i].id, "", "seed", (uint64_t)seed, execs, items[i].data, items[i].len, &ex,
                    save);
        execs++;
    }

    int cursor = 0;
    while (execs < (uint32_t)exec_budget && count > 0) {
        VrInput *base = &items[cursor % count];
        int energy = base->favored ? 8 : 2;
        for (int e = 0; e < energy && execs < (uint32_t)exec_budget; e++) {
            VrInput *splice = &items[vr_rng_below(&rng, (uint32_t)count)];
            uint8_t mut[VR_MAX_MUTATION_INPUT];
            char op[24];
            size_t mlen = vr_mutate(&rng, base->data, base->len, mut, sizeof mut, splice->data, splice->len, op,
                                    sizeof op);
            char id[17];
            id_of(mut, mlen, id);
            if (corpus_has(items, count, id)) {
                skipped++;
                continue;
            }
            VrExecOut ex;
            vr_execute(mut, mlen, (int)timeout, 1, &ex);
            int novel = ex.new_edges || ex.behavior_new;
            int fail = ex.exit_type == VR_EXIT_CRASH || ex.exit_type == VR_EXIT_SANITIZER ||
                       ex.exit_type == VR_EXIT_TIMEOUT;
            char sig[160];
            failure_signature(&ex, sig, sizeof sig);
            int new_sig = 0;
            if (fail) {
                new_sig = 1;
                for (int s = 0; s < nfail; s++) {
                    if (strcmp(seen_fail[s], sig) == 0) new_sig = 0;
                }
                if (new_sig && nfail < 64) {
                    snprintf(seen_fail[nfail], sizeof seen_fail[nfail], "%s", sig);
                    nfail++;
                }
            }
            int save = novel || new_sig;
            if (save) {
                const char *dest = ex.exit_type == VR_EXIT_NORMAL ? corpus_dir : fail_dir;
                save_blob(dest, id, mut, mlen);
                add_corpus(items, &count, mut, mlen, base->id, op, novel);
            }
            if (ex.exit_type == VR_EXIT_CRASH) crashes++;
            if (ex.exit_type == VR_EXIT_SANITIZER) sanitizers++;
            if (ex.exit_type == VR_EXIT_TIMEOUT) timeouts++;
            write_event(events, id, base->id, op, (uint64_t)seed, execs, mut, mlen, &ex, save);
            execs++;
            if ((execs % 25u) == 0) {
                struct timespec ts;
                clock_gettime(CLOCK_MONOTONIC, &ts);
                uint64_t now = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
                write_progress(progress_path, execs, vr_engine_edges_seen(), vr_engine_behavior_keys(), crashes,
                               sanitizers, timeouts, (uint32_t)count, now - t0, vr_engine_guards());
                fflush(events);
            }
        }
        cursor++;
        if (cursor > count * 100000) break;
    }
    fclose(events);
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t elapsed = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL - t0;
    double rate = elapsed > 0 ? (double)execs * 1000.0 / (double)elapsed : 0;
    char exe[512];
    ssize_t el = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (el < 0) {
        snprintf(exe, sizeof exe, "vrfuzz");
    } else {
        exe[el] = 0;
    }
    FILE *sum = fopen(summary_path, "w");
    if (!sum) return 2;
    fprintf(sum,
            "{\"schema\":\"vectorrift.summary.v1\",\"target_id\":\"%s\",\"target_version\":\"%s\","
            "\"compiler\":\"clang-%d.%d\",\"coverage\":\"trace-pc-guard\","
            "\"sanitizers\":[\"address\",\"undefined\"],\"flags\":[\"-fsanitize=address,undefined\","
            "\"-fsanitize-coverage=trace-pc-guard\",\"-fno-sanitize-recover=all\",\"-O1\",\"-g\"],"
            "\"seed\":%ld,\"executions\":%u,\"skipped_duplicates\":%u,\"edges_seen\":%u,\"guards\":%u,"
            "\"behavior_keys\":%u,\"crashes\":%u,\"sanitizer_failures\":%u,\"timeouts\":%u,"
            "\"corpus_size\":%u,\"elapsed_ms\":%llu,\"execs_per_sec\":%.3f,\"binary\":",
            vr_target_id(), vr_target_version(), __clang_major__, __clang_minor__, seed, execs, skipped,
            vr_engine_edges_seen(), vr_engine_guards(), vr_engine_behavior_keys(), crashes, sanitizers,
            timeouts, (unsigned)count, (unsigned long long)elapsed, rate);
    json_escape(sum, exe);
    fprintf(sum, ",\"events\":");
    json_escape(sum, events_path);
    fputs("}\n", sum);
    fclose(sum);
    write_progress(progress_path, execs, vr_engine_edges_seen(), vr_engine_behavior_keys(), crashes, sanitizers,
                   timeouts, (uint32_t)count, elapsed, vr_engine_guards());
    fprintf(stdout, "%s\n", summary_path);
    for (int i = 0; i < count; i++) free(items[i].data);
    free(items);
    return 0;
}
