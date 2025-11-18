// Standalone host-side executable that embeds ITCM/DTCM sections
// and provides sim_entry/sim_fill like the previous .so, but as an EXE.
#include "include/simwork.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

// Optionally place a small marker blob in ITCM to ensure the section exists even without functions
// (Functions in simwork.c are already annotated into .text.itcm)
#if defined(__GNUC__)
__attribute__((section(".itcm"), used)) static const unsigned char k_itcm_marker[16] = {
  0x5A,0xDB,0x1E,0x00, 0xAA,0x55,0xCC,0x33, 0x10,0x20,0x30,0x40, 0x77,0x88,0x99,0x00
};
__attribute__((section(".dtcm.data"), used)) static float k_dtcm_marker[8] = {
  1.0f,2.0f,3.0f,4.0f,5.0f,6.0f,7.0f,8.0f
};
#endif

int main(int argc, char** argv) {
    // Optional stop right after program start to allow debugger attach/mapping discovery
    const char* stop_env = getenv("ZDB_STOP_AFTER_START");
    if (stop_env && *stop_env) {
        fprintf(stderr, "[HOST_EXE] ZDB_STOP_AFTER_START set; raising SIGSTOP before main work\n");
        fflush(stderr);
        raise(SIGSTOP);
    }

    // Matrix size can be overridden by first argument
    int n = 16;
    if (argc > 1) {
        int t = atoi(argv[1]);
        if (t > 0 && t <= 64) n = t;
    }

    float *A = (float*)malloc(n*n*sizeof(float));
    float *B = (float*)malloc(n*n*sizeof(float));
    float *C = (float*)malloc(n*n*sizeof(float));
    if (!A || !B || !C) {
        fprintf(stderr, "allocation failed\n");
        return 2;
    }

    sim_fill(A, (size_t)n*(size_t)n);
    sim_fill(B, (size_t)n*(size_t)n);
    memset(C, 0, (size_t)n*(size_t)n*sizeof(float));

    int chk = sim_entry(n, A, B, C);
    printf("sim_entry(n=%d) checksum=%d\n", n, chk);

    // Touch marker blobs to ensure the linker keeps sections even with aggressive GC
    // (this also gives mock_backend a predictable payload to read via read_mem if desired)
    volatile unsigned char touch = k_itcm_marker[0];
    volatile float fsum = k_dtcm_marker[0] + k_dtcm_marker[1];
    (void)touch; (void)fsum;

    free(A); free(B); free(C);
    return 0;
}