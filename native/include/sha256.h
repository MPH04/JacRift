#ifndef VR_SHA256_H
#define VR_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[64];
    uint32_t buflen;
} VrSha256;

void vr_sha256_init(VrSha256 *ctx);
void vr_sha256_update(VrSha256 *ctx, const uint8_t *data, size_t len);
void vr_sha256_final(VrSha256 *ctx, uint8_t out[32]);
void vr_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void vr_sha256_hex(const uint8_t *data, size_t len, char out[65]);

#endif
