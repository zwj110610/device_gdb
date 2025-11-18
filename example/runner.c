#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

typedef int  (*fn_entry_t)(int,const float*,const float*,float*);
typedef void (*fn_fill_t)(float*, size_t);

int main(int argc, char** argv) {
    const char* so_path = "./libsimwork.so"; // 默认：在 build 目录运行时直接加载同目录下的 .so
    const char* env_so = getenv("ZDB_SO");
    if (env_so && *env_so) {
        so_path = env_so;
    } else if (argc > 1 && argv[1] && argv[1][0]) {
        so_path = argv[1];
    }

    void* h = dlopen(so_path, RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen fail: %s (path=%s)\n", dlerror(), so_path);
        return 1;
    }

    fn_entry_t sim_entry = (fn_entry_t)dlsym(h, "sim_entry");
    fn_fill_t  sim_fill  = (fn_fill_t) dlsym(h, "sim_fill");
    if (!sim_entry || !sim_fill) {
        fprintf(stderr,"dlsym fail (sim_entry/sim_fill)\n");
        dlclose(h);
        return 2;
    }

    // Optional stop after dlopen/dlsym for debugger attachment/mapping discovery
    const char* stop_env = getenv("ZDB_STOP_AFTER_DLOPEN");
    if (stop_env && *stop_env) {
        fprintf(stderr, "[RUNNER] ZDB_STOP_AFTER_DLOPEN set; raising SIGSTOP before sim_entry\n");
        fflush(stderr);
        raise(SIGSTOP);
    }

    int n = 16;
    float *A = (float*)malloc(n*n*sizeof(float));
    float *B = (float*)malloc(n*n*sizeof(float));
    float *C = (float*)malloc(n*n*sizeof(float));
    sim_fill(A, n*n);
    sim_fill(B, n*n);
    memset(C, 0, n*n*sizeof(float));

    int chk = sim_entry(n, A, B, C);
    printf("sim_entry(n=%d) checksum=%d\n", n, chk);

    free(A); free(B); free(C);
    dlclose(h);
    return 0;
}
