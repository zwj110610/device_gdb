// Public API for simulation work used by both shared-lib and host executable
#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void sim_fill(float* buf, size_t n);
int  sim_entry(int n, const float* A, const float* B, float* C);

#ifdef __cplusplus
}
#endif