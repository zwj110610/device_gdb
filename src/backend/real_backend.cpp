#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <tuple>
#include <algorithm>
#include <fstream>
#include "zdb_backend.h"
#include "elf_loader.h"

namespace zdb {

// =============================================================
// Global State Control
// =============================================================
void shutdown() {
    std::puts("[REAL] shutdown(): not implemented yet");
}

bool reload() {
    std::puts("[REAL] reload(): not implemented yet");
    return false;
}

void reset() {
    std::puts("[REAL] reset(): not implemented yet");
}


// =============================================================
// Program Loading
// =============================================================
bool hex_load(const std::string& itcm_bin_path,
              const std::string& dtcm_bin_path,
              uint64_t itcm_addr,
              uint64_t dtcm_addr,
              bool wakeup,
              uint64_t boot_addr)
{
    std::printf("[REAL] hex_load(itcm=%s, dtcm=%s, itcm_addr=0x%llx, dtcm_addr=0x%llx, wakeup=%d, boot=0x%llx)\n",
                itcm_bin_path.c_str(),
                dtcm_bin_path.c_str(),
                (unsigned long long)itcm_addr,
                (unsigned long long)dtcm_addr,
                (int)wakeup,
                (unsigned long long)boot_addr);
    return false;
}


bool hex_load_elf(const std::string& elf_path,
                  uint64_t itcm_addr,
                  uint64_t dtcm_addr,
                  bool wakeup)
{
    std::printf("[REAL] hex_load_elf(elf=%s, itcm_addr=0x%llx, dtcm_addr=0x%llx, wakeup=%d)\n",
                elf_path.c_str(),
                (unsigned long long)itcm_addr,
                (unsigned long long)dtcm_addr,
                (int)wakeup);
    return false;
}


// =============================================================
// Execution Control
// =============================================================
void halt() {
    std::puts("[REAL] halt(): not implemented yet");
}

void cont() {
    std::puts("[REAL] cont(): not implemented yet");
}

void run() {
    // For hardware backend, 'run' is currently the same as 'cont'.
    // When implemented, 'run' should restart the program if supported by the target.
    std::puts("[REAL] run(): not implemented yet (alias of cont)");
}

void step(unsigned n) {
    std::printf("[REAL] step(%u): not implemented yet\n", n);
}

void stepl(unsigned n) {
    std::printf("[REAL] stepl(%u): not implemented yet\n", n);
}

uint64_t show_pc() {
    std::puts("[REAL] show_pc(): not implemented yet");
    return 0;
}

void get_status(std::string& state, uint64_t& pc, std::string& reason) {
    state = "unknown";
    pc = 0;
    reason = "not implemented";
}


// =============================================================
// Breakpoint Control
// =============================================================
bool bp_set(uint64_t addr, unsigned id) {
    std::printf("[REAL] bp_set(addr=0x%llx, id=%u): not implemented yet\n",
                (unsigned long long)addr, id);
    return false;
}

bool bp_del(unsigned id) {
    std::printf("[REAL] bp_del(id=%u): not implemented yet\n", id);
    return false;
}

bool bp_del_all() {
    std::puts("[REAL] bp_del_all(): not implemented yet");
    return false;
}

bool bp_enable(unsigned id) {
    std::printf("[REAL] bp_enable(id=%u): not implemented yet\n", id);
    return false;
}

bool bp_disable(unsigned id) {
    std::printf("[REAL] bp_disable(id=%u): not implemented yet\n", id);
    return false;
}

bool bp_list(std::vector<std::tuple<unsigned, uint64_t, bool>>& out) {
    out.clear();
    std::puts("[REAL] bp_list(): not implemented yet");
    return false;
}


// =============================================================
// Register & Memory
// =============================================================
void regs_scalar_print() {
    std::puts("[REAL] regs_scalar_print(): not implemented yet");
}

bool probe_vec(unsigned start, unsigned count, uint64_t& dump_addr) {
    std::printf("[REAL] probe_vec(start=%u, count=%u): not implemented yet\n", start, count);
    dump_addr = 0;
    return false;
}

bool probe_const(unsigned start, unsigned count, uint64_t& dump_addr) {
    std::printf("[REAL] probe_const(start=%u, count=%u): not implemented yet\n", start, count);
    dump_addr = 0;
    return false;
}

bool read_mem(uint64_t addr, size_t size, std::vector<uint8_t>& out) {
    std::printf("[REAL] read_mem(addr=0x%llx, size=%zu): not implemented yet\n",
                (unsigned long long)addr, size);
    return false;
}

bool write_mem(uint64_t addr, const std::vector<uint8_t>& data) {
    std::printf("[REAL] write_mem(addr=0x%llx, bytes=%zu): not implemented yet\n",
                (unsigned long long)addr, data.size());
    return false;
}


// =============================================================
// Mailbox / Core Info
// =============================================================
void get_mailbox(uint32_t& cmd, uint32_t& status, uint64_t& buf_addr, uint32_t& count) {
    cmd = status = count = 0;
    buf_addr = 0;
    std::puts("[REAL] get_mailbox(): not implemented yet");
}

CoreInfo get_core_info() {
    CoreInfo info;
    info.itcm_size   = 0;
    info.dtcm_size   = 0;
    info.dram_size   = 0;
    info.scalar_regs = 0;
    info.vector_regs = 0;
    info.const_regs  = 0;
    info.version     = "real-backend-stub";
    std::puts("[REAL] get_core_info(): not implemented yet");
    return info;
}

} // namespace zdb

// =============================
// Variables (backend-facing stubs)
// =============================
namespace zdb {

bool var_resolve(const std::string& /*name*/, VarInfoSimple& out) {
    out = VarInfoSimple{}; return false;
}

bool var_read_best_addr(const VarInfoSimple& /*info*/,
                        size_t /*size*/,
                        uint64_t& used_addr,
                        std::vector<uint8_t>& out) {
    used_addr = 0; out.clear(); return false;
}

} // namespace zdb

// =============================
// Command stubs (backend-side)
// =============================
namespace zdb {

void cmd_symbols_backend(){ std::puts("[REAL] symbols: not implemented in real backend"); }
void cmd_print_var_backend(const std::string& name, size_t size){ (void)name; (void)size; std::puts("[REAL] print: not implemented in real backend"); }
void cmd_watch_add_backend(const std::string& name, size_t size){ (void)name; (void)size; std::puts("[REAL] watch add: not implemented in real backend"); }
void cmd_watch_del_backend(const std::string& name){ (void)name; std::puts("[REAL] watch del: not implemented in real backend"); }
void cmd_watch_ls_backend(){ std::puts("[REAL] watch ls: not implemented in real backend"); }
void cmd_watch_poll_backend(){ std::puts("[REAL] watch poll: not implemented in real backend"); }

} // namespace zdb


