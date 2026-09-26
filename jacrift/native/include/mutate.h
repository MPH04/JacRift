#ifndef VR_MUTATE_H
#define VR_MUTATE_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t s;
} VrRng;

void vr_rng_seed(VrRng *rng, uint64_t seed);
uint64_t vr_rng_next(VrRng *rng);
uint32_t vr_rng_below(VrRng *rng, uint32_t n);

/* Writes a mutated input into `out`. Returns length. `op_name` receives a
   short stable label (bitflip, byte, interest8, interest16, interest32,
   delete, insert, splice, overwrite). */
size_t vr_mutate(VrRng *rng, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap,
                 const uint8_t *splice, size_t splice_len, char *op_name, size_t op_cap);

#endif
