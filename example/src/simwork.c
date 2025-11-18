#include "simwork.h"
#include <math.h>
#include <stdint.h>
#include <string.h>

#define SEC_ITCM   __attribute__((section(".text.itcm")))
#define SEC_DTCM   __attribute__((section(".dtcm.data")))
#define NOINLINE   __attribute__((noinline))

SEC_DTCM static float g_bias[256];
SEC_DTCM static float g_tmp[1024];

static void init_bias(void) {
    for (int i=0;i<256;++i) g_bias[i] = (float)(i%13) * 0.031f;
}

SEC_ITCM NOINLINE
static void mm_naive(int n, const float* A, const float* B, float* C) {
    for (int i=0;i<n;i++) {
        for (int j=0;j<n;j++) {
            float acc = 0.f;
            for (int k=0;k<n;k++) acc += A[i*n+k]*B[k*n+j];
            C[i*n+j] = acc;
        }
    }
}

SEC_ITCM NOINLINE
static void relu_bias(int n, float* C) {
    for (int i=0;i<n*n;i++) {
        float x = C[i] + g_bias[i % 256];
        C[i] = x > 0.f ? x : 0.f;
    }
}

void SEC_ITCM sim_fill(float* buf, size_t n) {
    for (size_t i=0;i<n;i++) buf[i] = (float)(i%7) * 0.1f;
}

int SEC_ITCM sim_entry(int n, const float* A, const float* B, float* C) {
    if (n <= 0 || n > 32) return -1;
    init_bias();
    mm_naive(n, A, B, C);
    relu_bias(n, C);

    volatile double s = 0.0;
    for (int i=0;i<n*n;i++) s += C[i];
    return (int)lrint(s);
}
