#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <tuple>
#include <unordered_map>
#include "config.h"

namespace zdb {
struct CoreInfo {
  size_t itcm_size = 0;
  size_t dtcm_size = 0;
  size_t dram_size = 0;
  unsigned scalar_regs = 0;
  unsigned vector_regs = 0;
  unsigned const_regs  = 0;
  std::string version;  
};
CoreInfo get_core_info();
struct Breakpoint {
  unsigned   id = 0;
  uint64_t   addr = 0;
  bool       enabled = true;
};
struct CsuContext {
  unsigned id = 0;
  bool running = false;
  bool halted  = true;
  uint64_t pc  = 0;
  std::string reason;
  unsigned next_bp_id = 1;
  std::unordered_map<unsigned, Breakpoint> bp_by_id;
  std::unordered_map<uint64_t, unsigned>   bp_id_by_addr;
  std::vector<uint8_t> itcm, dtcm, dram;
  struct { uint32_t cmd=0, status=0; uint64_t buf_addr=0; uint32_t count=0; } mbox;
  std::vector<uint64_t> scalar;  // 32 x 64-bit
  std::vector<uint8_t>  vregs;   // 64 regs * 64B
  std::vector<uint8_t>  cregs;   // 64 regs * 64B
  // Host attach state (Linux prototype)
  int host_pid = -1;
  bool host_attached = false;
  // Loaded ELF path (for host .so identification)
  std::string loaded_elf_path;
  // Runtime mapping range of the loaded .so in the host process
  uint64_t host_so_base = 0;
  uint64_t host_so_end  = 0;
} ;

extern   CsuContext g;
bool init(unsigned csu_id = 0);
void shutdown();
void reset();

bool hex_load(const std::string& itcm_bin_path,
                   const std::string& dtcm_bin_path,
                   uint64_t itcm_addr,
                   uint64_t dtcm_addr,
                   bool wakeup,
                   uint64_t boot_addr) ;
                   
bool hex_load_elf(const std::string& elf_path,
                  uint64_t itcm_addr,
                  uint64_t dtcm_addr,
                  bool wakeup);


void halt();
// Run from the beginning (host-mode: restart the process each time; device-mode: alias to cont)
void run();
void cont();
void step(unsigned n = 1);
void stepl(unsigned n = 1);
uint64_t show_pc();
void get_status(std::string& state, uint64_t& pc, std::string& reason);

bool bp_set(uint64_t addr, unsigned id = 0);
bool bp_del(unsigned id);
bool bp_del_all();
bool bp_enable(unsigned id);
bool bp_disable(unsigned id);
bool bp_list(std::vector<std::tuple<unsigned, uint64_t, bool>>& out);

void regs_scalar_print();
bool probe_vec(unsigned start, unsigned count, uint64_t& dump_addr);
bool probe_const(unsigned start, unsigned count, uint64_t& dump_addr);


bool read_mem(uint64_t addr, size_t size, std::vector<uint8_t>& out);
bool write_mem(uint64_t addr, const std::vector<uint8_t>& data);
void get_mailbox(uint32_t& cmd, uint32_t& status, uint64_t& buf_addr, uint32_t& count);//reserve
bool reload(); 

// Test helper: enable a driver-path stub so memory ops go through
// driver interfaces even without a real driver/device.
void enable_driver_stub();

#if DEVPORT(LINUX)
// ===== Host attach (Linux prototype) =====
// Launch an executable under ptrace and attach to it. Returns true on success.
bool host_attach_exe(const std::string& exe_path, const std::vector<std::string>& args);
// Attach to an existing process by pid. Returns true on success.
bool host_attach_pid(int pid);
// Detach from currently attached process.
bool host_detach();
// Single-step the attached process by n instructions and update pc.
bool host_stepi(unsigned n = 1);
// Continue the attached process until next stop (signal/break).
bool host_cont();
#endif

// =============================
// Variables (backend-facing)
// =============================

struct VarInfoSimple {
  bool      is_global = true;   
  bool      is_reg = false;     
  int       regnum = -1;        
  uint64_t  addr = 0;           
};


bool var_resolve(const std::string& name, VarInfoSimple& out);


bool var_read_best_addr(const VarInfoSimple& info,
                        size_t size,
                        uint64_t& used_addr,
                        std::vector<uint8_t>& out);


void cmd_symbols_backend();
void cmd_print_var_backend(const std::string& name, size_t size);
void cmd_watch_add_backend(const std::string& name, size_t size);
void cmd_watch_del_backend(const std::string& name);
void cmd_watch_ls_backend();
void cmd_watch_poll_backend();

} // namespace zdb

