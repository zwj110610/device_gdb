/**
 * @file regs.cpp
 * @author zhangweijie
 * @date 2025/11/3
 * @brief The implementation of interfaces related to reading and writing zpu registers and memory.
 *
 * Copyright (C) 2025 Sunmmio Inc.
 * All right reserved.
 *
 * This file is a part of SuBase, which is the foundation of Sunmmio's ZPU.
 */
#include <cstdio>
#include <vector>
#include <string>
#include <cstdint>
#include "zdb_backend.h"        
#include "zdb_cmd.h"

namespace cmd {

uint64_t pc() {
    return zdb::show_pc();
}

void regs(const std::string& which) {
    

    uint64_t dump_addr = 0;
    if (which == "vector") {
        if (zdb::probe_vec(0, 4, dump_addr))
            std::printf("vector dump @0x%llx\n", (unsigned long long)dump_addr);
        else
            std::puts("probe vector FAIL");
    } else if (which == "const") {
        if (zdb::probe_const(0, 4, dump_addr))
            std::printf("const dump @0x%llx\n", (unsigned long long)dump_addr);
        else
            std::puts("probe const FAIL");
    }else if (which == "scalar") {
        zdb::regs_scalar_print();
     }else {
        std::puts("usage: regs [scalar|vector|const]");
    }
}

void read_mem(uint64_t addr, size_t size,std::vector<uint8_t>& out) {
    
    if (!zdb::read_mem(addr, size, out)) {
        std::puts("READ FAIL");
        return;
    }
    for (size_t i = 0; i < out.size(); ++i) {
        if (i % 16 == 0) std::printf("\n0x%08llx: ", (unsigned long long)(addr + i));
        std::printf("%02x ", out[i]);
    }
    std::puts("");
}

void write_mem(uint64_t addr, const std::vector<uint8_t>& data) {
    if (zdb::write_mem(addr, data)) std::puts("WRITE OK");
    else std::puts("WRITE FAIL");
}

} // namespace cmd
