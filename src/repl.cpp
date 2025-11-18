
#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include "zdb_backend.h"   
#include "elf_loader.h"
#include "zdb_cmd.h"
#include "config.h"
// ---------------------- helpers ----------------------
static std::vector<std::string> split_ws(const std::string& s) {
    std::istringstream iss(s);
    std::vector<std::string> out;
    std::string tok;
    while (iss >> tok) out.push_back(tok);
    return out;
}

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return s;
}
static inline bool ends_with_ci(const std::string& s, const char* suf) {
    auto S = lower(s), T = lower(std::string(suf));
    return S.size() >= T.size() && S.compare(S.size()-T.size(), T.size(), T) == 0;
}

/*
static bool ieq(const std::string& a, const std::string& b) {
    return lower(a) == lower(b);
}*/
static unsigned long long parse_u64(const std::string& s) {
    return std::stoull(s, nullptr, 0); // accepts 0x.. and decimal
}

static const std::unordered_map<std::string, const char*> kHelpDetail = {
  {"hex-load", R"(hex-load — Load program into ITCM/DTCM (BIN or ELF executable)

BIN mode:
  hex-load --itcm <itcm.bin> --dtcm <dtcm.bin>
           [--itcm-addr 0xADDR] [--dtcm-addr 0xADDR]
           [--boot 0xADDR] [--wakeup] [--no-repl]
  Notes:
    • Writes ITCM bin to ITCM[--itcm-addr], DTCM bin to DTCM[--dtcm-addr]
    • PC will be set to --itcm-addr
    • --wakeup: run after load

ELF executable mode (host-side EXE or device-side ELF):
  hex-load <image>
           [--itcm-addr 0xADDR] [--dtcm-addr 0xADDR]
           [--boot 0xADDR] [--wakeup] [--no-repl]
  Defaults (if not provided): --itcm-addr=0x10000, --dtcm-addr=0x1A0000
  Notes:
    • <image> can be a host-side executable (PIE or non-PIE, with or without extension),
      or a device-side ELF file
    • Extracts .text/.data-like sections and copies to ITCM/DTCM at given addrs
    • PC resolved by symbol `_start` → `main` → section base → 0
    • --wakeup: run after load

Examples:
  hex-load --itcm build/itcm.bin --dtcm build/dtcm.bin --itcm-addr 0x10000 --dtcm-addr 0x1A0000 --wakeup
  hex-load out/firmware.elf --wakeup
  hex-load source/executables/sim/build/host_exec --wakeup
)"},
  {"run",        "run — Restart and run to first enabled breakpoint (host-mode). If device-mode, behaves like 'cont'.\n"},
  {"reload",     "reload — Reload last images .\n"},
  {"load-assist","load-assist <file> — Helper hook for scripted loading utilities.\n"},
  {"halt",       "halt — Halt the target.\n"},
  {"cont",       "cont — Continue execution.\n"},
  {"step",       "step [n] — Single-step n instructions (default 1).\n"},
  {"stepl",      "stepl [n] — Source-level step (line). Currently same as 'step n'.\n"},
  {"status",     "status — Print run state, PC and reason.\n"},
  {"bp", R"(bp — Breakpoint management

  bp set [pc|0xADDR|<file>:<line>|:<line>] [--id N]
                                   Set a breakpoint; --id optional (auto-assigned if omitted)
  bp del [--id N|--all]           Delete one breakpoint or all
  bp en  [--id N]                 Enable a breakpoint
  bp dis [--id N]                 Disable a breakpoint
  bp ls                           List breakpoints

Examples:
  bp set pc
  bp set 0x80001234
  bp set simwork.c:42
  bp set :42
  bp en --id 3
  bp del --id 3
  bp del --all
)"},
  {"regs", R"(regs — Register inspection

  regs                → same as 'regs scalar'
  regs scalar         → print scalar registers
  regs vector         → dump first 4 vector regs into DRAM (prints dump address)
  regs const          → dump first 4 const  regs into DRAM (prints dump address)
)"},
  {"read-mem",  "read-mem <addr> <size> — Hex dump memory (16 bytes per line).\n"},
  {"write-mem", "write-mem <addr> <byte1> [byte2 ...] — Write raw bytes to memory.\n"},
  {"dump-mem",  "dump-mem <addr> <size> <file> — Dump memory region to a file.\n"},
  {"load-mem",  "load-mem <addr> <file> — Load a file's content into memory at addr.\n"},
  {"symbols",   "symbols — List defined ELF symbols (name and address).\n"},
  {"print",     "print <name> [size] — Resolve symbol/local and print its value.\n"},
  {"watch",     R"(watch — Monitor variable changes

  watch add <name> [size]   Add a watch (size default 8)
  watch del <name>          Remove a watch
  watch ls                  List watches
  watch poll                Poll all watches and print changes
)"},
  {"version",   "version — Print version and active backend.\n"},
  {"quit",      "quit | exit — Leave the REPL.\n"},
  {"exit",      "quit | exit — Leave the REPL.\n"},
  {"help",      "help [cmd] — Show all command usages, or detailed usage for a specific command.\n"},
};


static void print_help_all() {
 
    const std::vector<std::string> order = {
        "hex-load","run","reload","load-assist",
        "halt","cont","step","stepl","status",
        "bp","regs",
        "read-mem","write-mem","dump-mem","load-mem",
        "symbols","print","watch",
        "version","help","quit","exit"
    };
    std::cout <<
"============================================================\n"
"ZDB Help — all commands\n"
"============================================================\n\n";
    for (const auto& name : order) {
        auto it = kHelpDetail.find(name);
        if (it != kHelpDetail.end()) {
            std::cout << ">>> " << name << "\n";
            std::cout << it->second;
            if (it->second[strlen(it->second)-1] != '\n') std::cout << "\n";
            std::cout << "------------------------------------------------------------\n";
        }
    }
    std::cout <<
"Hints:\n"
"  • Addresses accept decimal or 0x-prefixed hex.\n"
"  • ELF defaults: --itcm-addr=0x10000, --dtcm-addr=0x1A0000.\n\n"
<< std::flush;
}


static void print_help_cmd(std::string name) {
    name = lower(name);
    auto it = kHelpDetail.find(name);
    if (it != kHelpDetail.end()) {
        std::cout << ">>> " << name << "\n" << it->second << std::flush;
    } else {
        std::cout << "No detailed help for '" << name
                  << "'. Try 'help' to see all commands.\n" << std::flush;
    }
}



// ---------------------- backend wrappers ----------------------
static void do_hex_load(const std::string& itcm,
                        const std::string& dtcm,
                        unsigned long long itcm_addr,
                        unsigned long long dtcm_addr,
                        bool wakeup,
                        bool norepl,
                        uint64_t boot_addr)
{
    // If a single positional file is provided (no --dtcm), treat it as an ELF/IMAGE
    // regardless of extension. This enables loading host executables directly.
    const bool image_mode = !itcm.empty() && dtcm.empty();
    if (image_mode) {
        
        const uint64_t iaddr = itcm_addr ? itcm_addr : 0x10000ULL;
        const uint64_t daddr = dtcm_addr ? dtcm_addr : 0x1A0000ULL;

        if (!cmd::hex_load_elf(/*elf*/itcm, /*itcm_addr*/iaddr, /*dtcm_addr*/daddr,
                               /*wakeup*/wakeup)) {
            std::puts("LOAD FAIL (ELF/IMAGE)");
            return;
        }
        std::puts("LOAD OK (ELF/IMAGE)");
        if (boot_addr) {
            std::printf("NOTE: boot address 0x%lx requested (backend may ignore in mock)\n", boot_addr);
        }
        return;
    }


    if (itcm.empty() || dtcm.empty()) {
        std::puts("usage:\n"
                  "  hex-load --itcm <itcm.bin> --dtcm <dtcm.bin>\n"
                  "           [--itcm-addr 0x..] [--dtcm-addr 0x..] [--wakeup]\n"
                  "  hex-load <image> [--itcm-addr 0x..] [--dtcm-addr 0x..] [--wakeup]\n"
                  "    where <image> is a host executable or device ELF (.elf or no extension)");
        return;
    }

    if (!cmd::hex_load(/*itcm*/itcm, /*dtcm*/dtcm,
                       /*itcm_addr*/itcm_addr, /*dtcm_addr*/dtcm_addr,
                       /*wakeup*/wakeup,/*boot*/boot_addr)) {
        std::puts("LOAD FAIL");
        return;
    }
    std::puts("LOAD OK");
    if (boot_addr) {
        std::printf("NOTE: boot address 0x%lx requested (backend may ignore in mock)\n", boot_addr);
    }
    (void)norepl; // --no-repl flag has no effect inside REPL mode
}
static void do_run() {
    // Use dedicated run semantics: host-mode restarts each time; device-mode may alias to cont.
    cmd::run();
}
static void do_reload() {
    cmd::reload();
}
static void do_load_assist(const std::string& f) {
    if (f.empty()) { std::puts("usage: load-assist <file>"); return; }
    
    std::printf("load-assist '%s' (not implemented in backend)\n", f.c_str());
}

static void do_halt()                { cmd::halt(); }
static void do_cont()                { cmd::cont(); }
static void do_step(unsigned n)      { cmd::step(n); }
static void do_stepl(unsigned n)     {  cmd::stepl(n); }
// host attach/step are backend-internal in mock; no frontend commands
static void do_status() {
    cmd::status();
}

static void do_bp_set(const std::string& where, bool use_pc, int id) {
    // pc or numeric address
    if (use_pc) { cmd::bp_set(cmd::pc(), (unsigned)id); return; }

    // file:line or :line support
    auto pos = where.find(':');
    if (pos != std::string::npos) {
        std::string file = where.substr(0, pos);
        std::string line_str = where.substr(pos + 1);
        if (line_str.empty()) { std::puts("ERR: missing line after ':'"); return; }
        int line = (int)parse_u64(line_str);
        std::vector<uint64_t> addrs;
        if (file.empty()) {
            // Pure ":line" — gather all addresses mapped to this line across all files
            addrs = zdb::elfx::line_to_addresses(line);
        } else {
            // Try exact file string match first
            addrs = zdb::elfx::line_to_addresses(file, line);
            if (addrs.empty()) {
                // Fallback: fuzzy match by basename/suffix. Build candidate set for the line,
                // then filter by SourceLoc.file ending with the requested filename.
                auto all = zdb::elfx::line_to_addresses(line);
                if (!all.empty()) {
                    std::vector<uint64_t> filtered;
                    for (auto addr : all) {
                        auto loc = zdb::elfx::addr_to_source(addr);
                        if (loc.file.empty()) continue;
                        // Compare by basename or path suffix
                        std::string path = loc.file;
                        auto p = path.find_last_of("/\\");
                        std::string base = (p==std::string::npos) ? path : path.substr(p+1);
                        if (base == file || ends_with_ci(path, (std::string("/") + file).c_str()) || ends_with_ci(path, (std::string("\\") + file).c_str())) {
                            filtered.push_back(addr);
                        }
                    }
                    addrs.swap(filtered);
                    if (!addrs.empty()) {
                        std::printf("NOTE: using basename/suffix match for '%s' at line %d\n", file.c_str(), line);
                    }
                }
            }
        }
        if (addrs.empty()) { std::puts("ERR: no addresses for given source line"); return; }
        // Choose the first mapping; print hint if multiple
        uint64_t sel = addrs.front();
        if (addrs.size() > 1) std::printf("NOTE: %zu addresses mapped; using first\n", addrs.size());
        cmd::bp_set(sel, (unsigned)id);
        return;
    }

    // fallback: numeric address
    uint64_t addr = parse_u64(where);
    if (addr==0) { std::puts("ERR: bp set needs valid addr or 'pc' or file:line"); return; }
    cmd::bp_set(addr, (unsigned)id);
}
static void do_bp_del(bool all, int id) {
    if (all) cmd::bp_del_all();
    else {
        if (id < 0) { std::puts("bp del needs --id N or --all"); return; }
        cmd::bp_del((unsigned)id);
    }
    
}
static void do_bp_en(bool all, int id)  {
    if (all) std::puts("bp en --all (not tracked by id in mock)");
    else {
        if (id < 0) { std::puts("bp en needs --id N or --all"); return; }
        cmd::bp_en((unsigned)id);
    }
   
}
static void do_bp_dis(bool all, int id) {
    if (all) { std::puts("bp dis --all (not tracked by id in mock)");}
    else {
        if (id < 0) { std::puts("bp dis needs --id N or --all"); return; }
        cmd::bp_dis((unsigned)id);
    }
   
}
static void do_bp_ls()                  {
    cmd::bp_ls();
}

static void do_regs(const std::string& which_raw) {
    const auto which = lower(which_raw);
    cmd::regs(which);
}
static void do_read_mem(unsigned long long addr, unsigned long long size) {
    std::vector<uint8_t> buf;
    cmd::read_mem(addr, (size_t)size,buf);
    
}
static void do_write_mem(unsigned long long addr, const std::vector<unsigned>& bytes) {
    std::vector<uint8_t> data; data.reserve(bytes.size());
    for (auto b: bytes) data.push_back((uint8_t)(b & 0xFF));
    cmd::write_mem(addr, data);
    
}
static void do_dump_mem(unsigned long long addr, unsigned long long size, const std::string& file) {
    std::vector<uint8_t> buf;
    cmd::read_mem(addr, (size_t)size, buf);
    FILE* fp = std::fopen(file.c_str(), "wb");
    if (!fp) { std::puts("ERR: cannot open file"); return; }
    std::fwrite(buf.data(), 1, buf.size(), fp);
    std::fclose(fp);
    std::printf("dumped %zu bytes to '%s'\n", buf.size(), file.c_str());
}
static void do_load_mem(unsigned long long addr, const std::string& file) {
    FILE* fp = std::fopen(file.c_str(), "rb");
    if (!fp) { std::puts("ERR: cannot open file"); return; }
    std::vector<uint8_t> buf; uint8_t tmp[4096];
    size_t n;
    while ((n = std::fread(tmp,1,sizeof(tmp),fp))>0) buf.insert(buf.end(), tmp, tmp+n);
    std::fclose(fp);
    cmd::write_mem(addr, buf);
   
}

static void do_version() {

#if DEVPORT(LINUX)
    std::printf("zdb %s (backend=mock)\n", SUBASE_VERSION_STRING );
#elif DEVPORT(FPGA)
    std::printf("zdb %s (backend=real)\n", SUBASE_VERSION_STRING );
#else 
    std::printf("zdb %s (backend=real)\n", SUBASE_VERSION_STRING );
#endif
}

// ---------------------- command parsing ----------------------
static bool parse_bool_flag(const std::vector<std::string>& v, const std::string& f) {
    return std::find(v.begin(), v.end(), f) != v.end();
}

int run_repl() {
 
    cmd::init(0);

    std::string line;
    print_help_all();
    while (true) {
        std::cout << "zdb> " << std::flush;
        if (!std::getline(std::cin, line)) break;

        auto tok = split_ws(line);
        if (tok.empty()) continue;
        auto cmd = lower(tok[0]);

        // System
        if (cmd == "quit" || cmd == "exit") break;
        if (cmd == "help") { 
            if (tok.size() >= 2) print_help_cmd(tok[1]);
            else                 print_help_all(); 
            continue; 
        }
        if (cmd == "version") { do_version(); continue; }

        // Program Loading & Initialization
        if (cmd == "hex-load") {
            std::string itcm, dtcm;
            unsigned long long itcm_addr = 0, dtcm_addr = 0, boot = 0;
            bool wakeup = false, norepl = false;

            std::string elf;
            for (size_t i = 1; i < tok.size(); ++i) {
                const std::string& a = tok[i];
                if (a == "--itcm" && i + 1 < tok.size())       { itcm = tok[++i]; }
                else if (a == "--dtcm" && i + 1 < tok.size())  { dtcm = tok[++i]; }
                else if (a == "--itcm-addr" && i + 1 < tok.size()) { itcm_addr = parse_u64(tok[++i]); }
                else if (a == "--dtcm-addr" && i + 1 < tok.size()) { dtcm_addr = parse_u64(tok[++i]); }
                else if (a == "--boot" && i + 1 < tok.size())      { boot      = parse_u64(tok[++i]); }
                else if (a.rfind("--", 0) == 0) {
                    // boolean flags parsed below; unknown flags are ignored here
                } else {
                    if (elf.empty()) {
                        elf = a;
                    } else {
                        std::puts("usage: hex-load <image> [--itcm-addr 0x..] [--dtcm-addr 0x..] [--boot 0x..] [--wakeup] [--no-repl] | hex-load --itcm <itcm.bin> --dtcm <dtcm.bin> [--itcm-addr 0x..] [--dtcm-addr 0x..] [--boot 0x..] [--wakeup] [--no-repl]");
                        elf.clear();
                        itcm.clear();
                        dtcm.clear();
                        break;
                    }
                }
            }
            wakeup = parse_bool_flag(tok, "--wakeup");
            norepl = parse_bool_flag(tok, "--no-repl");

            if (!elf.empty()) {
                itcm = elf; // positional ELF path; dtcm must remain empty for ELF mode
            }

            do_hex_load(itcm, dtcm, itcm_addr, dtcm_addr, wakeup, norepl, boot);
            continue;
        }
        if (cmd == "run")         { do_run(); continue; }
        if (cmd == "reload")      { do_reload(); continue; }
        if (cmd == "load-assist") {
            if (tok.size() < 2) { std::puts("usage: load-assist <file>"); continue; }
            do_load_assist(tok[1]); continue;
        }

        // Execution Control
        if (cmd == "halt")        { do_halt(); continue; }
        if (cmd == "cont")        { do_cont(); continue; }
        if (cmd == "step")        {
            unsigned n = (tok.size() >= 2) ? (unsigned)parse_u64(tok[1]) : 1;
            do_step(n); continue;
        }
        if (cmd == "stepl")       {
            unsigned n = (tok.size() >= 2) ? (unsigned)parse_u64(tok[1]) : 1;
            do_stepl(n); continue;
        }
        // no attach/detach/stepi in frontend; stepl handles host stepping internally in mock
        if (cmd == "status")      { do_status(); continue; }

        // Breakpoints
        if (cmd == "bp") {
            if (tok.size() < 2) { std::puts("bp set/del/en/dis/ls ..."); continue; }
            auto sub = lower(tok[1]);

            if (sub == "ls") { do_bp_ls(); continue; }

            if (sub == "set") {
                bool use_pc = true;
                std::string addr_str;
                int id = 0;
                if (tok.size() >= 3 && lower(tok[2]) != "pc") {
                    use_pc = false; addr_str = tok[2];
                }
                for (size_t i = 3; i + 1 < tok.size(); ++i) {
                    if (tok[i] == "--id") { id = (int)parse_u64(tok[++i]); }
                }
                do_bp_set(addr_str, use_pc, id);
                continue;
            }

            if (sub == "del" || sub == "en" || sub == "dis") {
                bool all = false;
                int id = -1;
                for (size_t i = 2; i < tok.size(); ++i) {
                    if (tok[i] == "--all") all = true;
                    else if (tok[i] == "--id" && i + 1 < tok.size()) id = (int)parse_u64(tok[++i]);
                }
                if (sub == "del") do_bp_del(all, id);
                else if (sub == "en") do_bp_en(all, id);
                else do_bp_dis(all, id);
                continue;
            }

           std::puts("bp set/del/en/dis/ls ...");
            continue;
        }

        // Registers & Memory
        if (cmd == "regs") {
            std::string which = (tok.size() >= 2) ? tok[1] : "scalar";
            do_regs(which); continue;
        }
        if (cmd == "read-mem") {
            if (tok.size() < 3) { std::puts("usage: read-mem <addr> <size>"); continue; }
            do_read_mem(parse_u64(tok[1]), parse_u64(tok[2])); continue;
        }
        if (cmd == "write-mem") {
            if (tok.size() < 3) { std::puts("usage: write-mem <addr> <byte1> [byte2 ...]"); continue; }
            unsigned long long addr = parse_u64(tok[1]);
            std::vector<unsigned> bytes; bytes.reserve(tok.size()-2);
            for (size_t i = 2; i < tok.size(); ++i) bytes.push_back((unsigned)parse_u64(tok[i]));
            do_write_mem(addr, bytes); continue;
        }
        if (cmd == "dump-mem") {
            if (tok.size() < 4) { std::puts("usage: dump-mem <addr> <size> <file>"); continue; }
            do_dump_mem(parse_u64(tok[1]), parse_u64(tok[2]), tok[3]); continue;
        }
        if (cmd == "load-mem") {
            if (tok.size() < 3) { std::puts("usage: load-mem <addr> <file>"); continue; }
            do_load_mem(parse_u64(tok[1]), tok[2]); continue;
        }

        // Variables
        if (cmd == "symbols") { cmd::symbols(); continue; }
        if (cmd == "print") {
            if (tok.size() < 2) { std::puts("usage: print <name> [size]"); continue; }
            size_t sz = (tok.size() >= 3) ? (size_t)parse_u64(tok[2]) : 8;
            cmd::print_var(tok[1], sz); continue;
        }
        if (cmd == "watch") {
            if (tok.size() < 2) { std::puts("usage: watch add|del|ls|poll ..."); continue; }
            auto sub = lower(tok[1]);
            if (sub == "add") {
                if (tok.size() < 3) { std::puts("usage: watch add <name> [size]"); continue; }
                size_t sz = (tok.size() >= 4) ? (size_t)parse_u64(tok[3]) : 8;
                cmd::watch_add(tok[2], sz); continue;
            }
            if (sub == "del") {
                if (tok.size() < 3) { std::puts("usage: watch del <name>"); continue; }
                cmd::watch_del(tok[2]); continue;
            }
            if (sub == "ls") { cmd::watch_ls(); continue; }
            if (sub == "poll") { cmd::watch_poll(); continue; }
            std::puts("usage: watch add|del|ls|poll ...");
            continue;
        }

        std::puts("unknown command (type 'help' to see all)");
    }

   
    return 0;
}

