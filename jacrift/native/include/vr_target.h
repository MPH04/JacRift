#ifndef VR_TARGET_H
#define VR_TARGET_H

#include <stddef.h>
#include <stdint.h>

/* Target ABI. The fuzzer and the libFuzzer entry both call this.
   `data`/`n` describe one input. Targets must tolerate n == 0.
   Targets emit behavior only through vr_emit. They must not choose
   filenames, shell commands, or network endpoints. */

int vr_target_execute(const uint8_t *data, size_t n);
const char *vr_target_id(void);
const char *vr_target_version(void);

/* Implemented by the host (coverage engine or libFuzzer entry).
   kind/a/b are untrusted and will be charset-filtered. */
void vr_emit(const char *kind, const char *a, const char *b);

#define VR_MAX_MUTATION_INPUT 4096
#define VR_ABSOLUTE_INPUT_CAP 65536

#endif
