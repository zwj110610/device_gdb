
#pragma once

#include <string>
#include <vector>

namespace cmd {

// ===== Run control =====
void halt();                               // prints "HALT OK"
void cont();                               // prints "CONT OK"
void run();                                // alias of cont(); prints "RUN"
void reset();                              // prints "RESET (stub)" on mock
void status();                             // prints "status: <state>, pc=0x..., reason=..."
void init(unsigned csu_id);
// Step by N instructions (if n==0, treated as 1). Prints "STEP OK pc=0x..."
void step(unsigned n);
void stepl(unsigned n);
// REPL overload: current impl ignores args and steps once.
void step(const std::vector<std::string>& args);

// Show program counter: prints "PC = 0x...."
uint64_t pc();

// ===== Registers =====
// If args empty or "scalar" → print scalar registers.
// If "vector"/"const" → probe and report dump address; prints errors on failure.
void regs(const std::string& which);

// ===== Memory =====
// Read `size` bytes at `addr` and hex-dump 16B per line; prints READ FAIL on error.
void read_mem(uint64_t addr, size_t size,std::vector<uint8_t>& out);
// Write `data` vector to `addr`; prints WRITE OK/FAIL.
void write_mem(uint64_t addr, const std::vector<uint8_t>& data);

// ===== Image loading / reload =====
// Raw binaries via backend hex_load():
// usage: hex-load --itcm f1 --dtcm f2 [--itcm-addr 0x..] [--dtcm-addr 0x..] [--wakeup]
bool hex_load(const std::string& itcm,
                  const std::string& dtcm,
                  uint64_t itcm_addr,
                  uint64_t dtcm_addr,
                  bool wakeup,
                  uint64_t boot_addr);

// ELF loader extracting ITCM/DTCM sections, copying into buffers:
// usage: hex-load <file.elf> [--itcm-base 0x..] [--dtcm-base 0x..]
bool hex_load_elf(const std::string& elf_path,
                  uint64_t itcm_addr,
                  uint64_t dtcm_addr,
                  bool wakeup);

// Ask backend to reload (mock prints "[MOCK] reload not implemented yet")
void reload();

// Optional helper hook (currently prints usage / echo filename).
void load_assist(const std::string& path);

// ===== Breakpoints =====
void bp_set(uint64_t addr,unsigned id);                // auto id; prints "BP SET @0x..."/FAIL
void bp_ls();                              // list all BPs
void bp_dis(unsigned id);                  // disable BP id
void bp_en(unsigned id);                   // enable BP id
void bp_del(unsigned id);                  // delete BP id
void bp_del_all();                         // delete all; prints OK/FAIL

// ===== Mailbox / Core-Info =====
void mailbox();                            // prints mailbox fields
void core_info();                          // prints memory sizes, reg counts, version

// ===== Variables =====
void symbols();                             // list ELF-defined symbols
void print_var(const std::string& name, size_t size = 8); // print variable value
void watch_add(const std::string& name, size_t size = 8); // add a watch
void watch_del(const std::string& name);    // remove a watch
void watch_ls();                            // list all watches
void watch_poll();                          // poll and print changes

} // namespace cmd

