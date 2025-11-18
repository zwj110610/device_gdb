#include <cstdio>
#include <cstdint>
#include "zdb_backend.h"     
#include "zdb_cmd.h"

namespace cmd {

void status() {
    std::string st, reason; uint64_t pc = 0;
    zdb::get_status(st, pc, reason);
    std::printf("status: %s, pc=0x%llx, reason=%s\n",
                st.c_str(), (unsigned long long)pc, reason.c_str());
}

void bp_set(uint64_t addr,unsigned id) {
    if (zdb::bp_set(addr, id))
        std::printf("BP SET @0x%llx\n", (unsigned long long)addr);
    else
        std::puts("BP SET FAIL");
}

void bp_ls() {
    std::vector<std::tuple<unsigned, uint64_t, bool>> bps;
    if (!zdb::bp_list(bps)) {
        std::puts("BP LIST FAIL");
        return;
    }
    if (bps.empty()) {
        std::puts("No breakpoints.");
        return;
    }
    std::puts("ID      ADDRESS            STATE");
    std::puts("-----------------------------------");
    for (const auto& t : bps) {
        unsigned id; uint64_t addr; bool en;
        std::tie(id, addr, en) = t;
        std::printf("%-6u  0x%016llx  %s\n",
                    id, (unsigned long long)addr, en ? "ENABLED" : "DISABLED");
    }
}

void bp_dis(unsigned id) {
    if (id == 0) { std::puts("usage: bp dis --id N"); return; }
    if (zdb::bp_disable(id)) std::puts("BP DIS OK");
    else std::puts("BP DIS FAIL");
}

void bp_en(unsigned id) {
    if (id == 0) { std::puts("usage: bp en --id N"); return; }
    if (zdb::bp_enable(id)) std::puts("BP EN OK");
    else std::puts("BP EN FAIL");
}

void bp_del(unsigned id) {
    if (id == 0) { std::puts("usage: bp del --id N"); return; }
    if (zdb::bp_del(id)) std::puts("BP DEL OK");
    else std::puts("BP DEL FAIL");
}

void bp_del_all() {
    if (zdb::bp_del_all()) std::puts("BP DEL ALL OK");
    else std::puts("BP DEL ALL FAIL");
}

// ===== Mailbox / Core-Info =====
void mailbox() {
    uint32_t cmd=0, status=0, count=0;
    uint64_t buf_addr=0;
    zdb::get_mailbox(cmd, status, buf_addr, count);

    std::puts("Mailbox:");
    std::printf("  cmd     = %u\n", cmd);
    std::printf("  status  = %u\n", status);
    std::printf("  buf_addr= 0x%llx\n", (unsigned long long)buf_addr);
    std::printf("  count   = %u\n", count);
}

void core_info() {
    auto info = zdb::get_core_info();
    std::puts("Core-Info:");
    std::printf("  ITCM size   : %zu bytes\n", info.itcm_size);
    std::printf("  DTCM size   : %zu bytes\n", info.dtcm_size);
    std::printf("  DRAM size   : %zu bytes\n", info.dram_size);
    std::printf("  Scalar regs : %u\n", info.scalar_regs);
    std::printf("  Vector regs : %u\n", info.vector_regs);
    std::printf("  Const regs  : %u\n", info.const_regs);
    std::printf("  Version     : %s\n", info.version.c_str());
}

} // namespace cmd
