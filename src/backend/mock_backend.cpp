#include "zdb_backend.h"
#include <vector>
#include <unordered_map>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <fstream>   // for std::ifstream, std::ofstream
#include <iterator>  // for std::istreambuf_iterator
#include <tuple>     // for std::tuple
#include <filesystem> // for std::filesystem::current_path
#include <cstdlib>    // for std::getenv
#include <sstream>    // for std::istringstream
#include <cerrno>     // for errno
#if DEVPORT(LINUX)
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#endif
#include <stdlib.h>
#include "elf_loader.h"
// Standalone build: no external driver interfaces; use local mock memory.

namespace {
// Parse /proc/<pid>/maps and find the base and end address for a given image (executable)
// The match is done using either full path or basename, preferring executable segments.
static bool find_image_base_in_maps(int pid, const std::string& image_path_or_name, uint64_t& base_out, uint64_t& end_out) {
  base_out = 0; end_out = 0;
  if (image_path_or_name.empty()) return false;
  // Match by basename if full path is not present in maps
  auto pos = image_path_or_name.find_last_of("/\\");
  std::string basename = (pos==std::string::npos) ? image_path_or_name : image_path_or_name.substr(pos+1);
  char maps_path[64]; std::snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
  std::ifstream ifs(maps_path);
  if (!ifs.good()) return false;
  std::string line;
  uint64_t first_base=0, first_end=0;
  uint64_t best_x_base=0, best_x_end=0;
  while (std::getline(ifs, line)) {
    // Format: start-end perms offset dev inode pathname
    // We only care about start,end and pathname
    std::istringstream iss(line);
    std::string range, perms, offset, dev, inode, path;
    if (!(iss >> range >> perms >> offset >> dev >> inode)) continue;
    std::getline(iss, path); // leading space remains
    if (!path.empty() && path[0]==' ') path.erase(0,1);
    if (path.empty()) continue;
    // Compare by basename or full path
    if (path.find(basename) == std::string::npos && path != image_path_or_name) continue;
    auto dash = range.find('-'); if (dash==std::string::npos) continue;
    std::string start_hex = range.substr(0,dash);
    std::string end_hex = range.substr(dash+1);
    errno = 0;
    char* ep1=nullptr; char* ep2=nullptr;
    unsigned long long start = std::strtoull(start_hex.c_str(), &ep1, 16);
    unsigned long long end   = std::strtoull(end_hex.c_str(), &ep2, 16);
    if (errno!=0 || ep1==start_hex.c_str() || ep2==end_hex.c_str()) continue;
    // Prefer executable mappings (perms like "r-xp"); if multiple, choose the largest
    if (perms.size()>=3 && perms[2]=='x') {
      if ((best_x_end - best_x_base) < (end - start)) { best_x_base = start; best_x_end = end; }
    }
    if (first_base==0) { first_base = start; first_end = end; }
  }
  if (best_x_base) { base_out = best_x_base; end_out = best_x_end; return true; }
  if (first_base)   { base_out = first_base; end_out = first_end; return true; }
  return false;
}

// Variant: find the executable mapping of the given image (executable) that contains a specific PC.
static bool find_image_exec_map_for_pc(int pid, const std::string& image_path_or_name, uint64_t pc, uint64_t& base_out, uint64_t& end_out) {
  base_out = 0; end_out = 0;
  if (image_path_or_name.empty()) return false;
  auto pos = image_path_or_name.find_last_of("/\\");
  std::string basename = (pos==std::string::npos) ? image_path_or_name : image_path_or_name.substr(pos+1);
  char maps_path[64]; std::snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
  std::ifstream ifs(maps_path);
  if (!ifs.good()) return false;
  std::string line;
  while (std::getline(ifs, line)) {
    std::istringstream iss(line);
    std::string range, perms, offset, dev, inode, path;
    if (!(iss >> range >> perms >> offset >> dev >> inode)) continue;
    std::getline(iss, path);
    if (!path.empty() && path[0]==' ') path.erase(0,1);
    if (path.empty()) continue;
    if (path.find(basename) == std::string::npos && path != image_path_or_name) continue;
    auto dash = range.find('-'); if (dash==std::string::npos) continue;
    errno = 0;
    unsigned long long start = std::strtoull(range.substr(0,dash).c_str(), nullptr, 16);
    unsigned long long end   = std::strtoull(range.substr(dash+1).c_str(), nullptr, 16);
    if (!(perms.size()>=3 && perms[2]=='x')) continue; // require executable
    if (pc >= start && pc < end) { base_out = start; end_out = end; return true; }
  }
  return false;
}

// Read the resolved path of /proc/<pid>/exe; return empty string on failure.
static std::string get_pid_exe_path(int pid) {
  char linkpath[64]; std::snprintf(linkpath, sizeof(linkpath), "/proc/%d/exe", pid);
  char buf[4096];
  ssize_t n = readlink(linkpath, buf, sizeof(buf)-1);
  if (n <= 0) return std::string();
  buf[n] = '\0';
  return std::string(buf);
}

// Run to a specific address by planting a temporary INT3 breakpoint.
// On success, child stops with SIGTRAP at 'addr'; we restore original word and reset RIP to 'addr'.
static bool run_to_addr_with_int3(int pid, uint64_t addr, uint64_t& stop_pc) {
  errno = 0;
  long orig_word = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, nullptr);
  if (orig_word == -1 && errno != 0) { std::perror("ptrace(PEEKDATA)"); return false; }
  long patched = (orig_word & ~0xFFL) | 0xCCL; // INT3 in low byte
  if (ptrace(PTRACE_POKEDATA, pid, (void*)addr, (void*)patched) != 0) { std::perror("ptrace(POKEDATA)"); return false; }
  if (ptrace(PTRACE_CONT, pid, 0, 0) != 0) { std::perror("ptrace(CONT)"); (void)ptrace(PTRACE_POKEDATA, pid, (void*)addr, (void*)orig_word); return false; }
  int st = 0;
  if (waitpid(pid, &st, 0) < 0) { std::perror("waitpid"); (void)ptrace(PTRACE_POKEDATA, pid, (void*)addr, (void*)orig_word); return false; }
  if (!WIFSTOPPED(st)) { std::printf("[HOST] child not stopped after CONT\n"); (void)ptrace(PTRACE_POKEDATA, pid, (void*)addr, (void*)orig_word); return false; }
  // Restore original instruction word
  if (ptrace(PTRACE_POKEDATA, pid, (void*)addr, (void*)orig_word) != 0) { std::perror("ptrace(POKEDATA restore)"); return false; }
  // Reset RIP to addr (x86_64-only)
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0) { std::perror("ptrace(GETREGS)"); return false; }
  regs.rip = addr;
  if (ptrace(PTRACE_SETREGS, pid, 0, &regs) != 0) { std::perror("ptrace(SETREGS)"); return false; }
  stop_pc = addr;
  return true;
}
} // anon

namespace zdb {

CsuContext g;
} // namespace zdb

// =============================
// Variables (backend-facing)
// =============================
#if DEVPORT(LINUX)
static bool dwarf_reg_to_value_x86_64_backend(int regnum, const user_regs_struct& regs, uint64_t& val_out){
  switch (regnum) {
    case 0:  val_out = regs.rax; return true;
    case 1:  val_out = regs.rdx; return true;
    case 2:  val_out = regs.rcx; return true;
    case 3:  val_out = regs.rbx; return true;
    case 4:  val_out = regs.rsi; return true;
    case 5:  val_out = regs.rdi; return true;
    case 6:  val_out = regs.rbp; return true;
    case 7:  val_out = regs.rsp; return true;
    case 8:  val_out = regs.r8;  return true;
    case 9:  val_out = regs.r9;  return true;
    case 10: val_out = regs.r10; return true;
    case 11: val_out = regs.r11; return true;
    case 12: val_out = regs.r12; return true;
    case 13: val_out = regs.r13; return true;
    case 14: val_out = regs.r14; return true;
    case 15: val_out = regs.r15; return true;
    case 16: val_out = regs.rip; return true;
    default: return false;
  }
}
#endif

namespace zdb {

bool var_resolve(const std::string& name, VarInfoSimple& out) {
  out = VarInfoSimple{};
  
  uint64_t pc = show_pc();
  uint64_t elf_pc = pc;
  if (!elfx::is_riscv_elf() && g.host_attached && g.host_so_base && pc >= g.host_so_base && pc < g.host_so_end) {
    uint64_t elf_base = elfx::next_addr(0);
    if (elf_base) elf_pc = elf_base + (pc - g.host_so_base);
  }

  elfx::VarInfo vi;
  if (!elfx::resolve_variable(name, elf_pc, vi)) return false;

  if (vi.is_global) {
    out.is_global = true; out.is_reg = false; out.regnum = -1; out.addr = vi.addr; return true;
  }

  if (vi.in_register && !vi.is_breg) {
    out.is_global = false; out.is_reg = true; out.regnum = vi.regnum; out.addr = 0; return true;
  }

  out.is_global = false; out.is_reg = false; out.regnum = -1; out.addr = 0;

  if (!vi.in_register) {
    uint64_t fp = 0;
#if DEVPORT(LINUX)
    if (g.host_attached) {
      user_regs_struct regs{};
      if (ptrace(PTRACE_GETREGS, g.host_pid, 0, &regs) == 0) fp = regs.rbp;
    }
#endif
    if (fp == 0 && g.scalar.size() > 8) fp = g.scalar[8];
    int64_t off = static_cast<int64_t>(vi.addr);
    if (vi.uses_cfa_base) fp += 16; // SysV AMD64：CFA ~= rbp + 16
    out.addr = static_cast<uint64_t>(static_cast<int64_t>(fp) + off);
    return true;
  }

  if (vi.in_register && vi.is_breg) {
    uint64_t base = 0;
#if DEVPORT(LINUX)
    if (g.host_attached) {
      user_regs_struct regs{};
      if (ptrace(PTRACE_GETREGS, g.host_pid, 0, &regs) == 0) {
        (void)dwarf_reg_to_value_x86_64_backend(vi.regnum, regs, base);
      }
    }
#endif
    if (base == 0 && g.scalar.size() > static_cast<size_t>(vi.regnum)) base = g.scalar[vi.regnum];
    out.addr = base + static_cast<int64_t>(vi.breg_offset);
    return true;
  }

  return false;
}

#if DEVPORT(LINUX)

static bool read_host_mem_ptrace(uint64_t addr, size_t size, std::vector<uint8_t>& out) {
  out.clear();
  if (!g.host_attached || g.host_pid <= 0) return false;
  if (size == 0) return true;
  size_t done = 0;
  while (done < size) {
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, g.host_pid, (void*)(addr + done), nullptr);
    if (word == -1 && errno != 0) { std::perror("ptrace(PEEKDATA)"); return false; }
    size_t take = std::min<size_t>(sizeof(long), size - done);
    for (size_t i = 0; i < take; ++i) {
      uint8_t byte = static_cast<uint8_t>((word >> (8*i)) & 0xFF);
      out.push_back(byte);
    }
    done += take;
  }
  return true;
}
#endif

bool var_read_best_addr(const VarInfoSimple& info,
                        size_t size,
                        uint64_t& used_addr,
                        std::vector<uint8_t>& out) {
  used_addr = 0; out.clear();

  if (info.is_reg) {
#if DEVPORT(LINUX)
    if (g.host_attached) {
      user_regs_struct regs{};
      if (ptrace(PTRACE_GETREGS, g.host_pid, 0, &regs) != 0) return false;
      uint64_t val = 0; if (info.regnum < 0) return false;
      if (!dwarf_reg_to_value_x86_64_backend(info.regnum, regs, val)) return false;
      out.assign(size, 0);
      for (size_t i=0;i<size && i<8;i++) out[i] = static_cast<uint8_t>((val >> (8*i)) & 0xFF);
      used_addr = 0; return true;
    }
#endif
    if (info.regnum >= 0 && g.scalar.size() > static_cast<size_t>(info.regnum)) {
      uint64_t val = g.scalar[info.regnum];
      out.assign(size, 0);
      for (size_t i=0;i<size && i<8;i++) out[i] = static_cast<uint8_t>((val >> (8*i)) & 0xFF);
      used_addr = 0; return true;
    }
    return false;
  }

  uint64_t vaddr = info.addr;
  if (g.host_attached) {
    uint64_t host_addr = vaddr;
    if (info.is_global) {
      uint64_t elf_base = elfx::next_addr(0);
      if (g.host_so_base && elf_base && vaddr >= elf_base) host_addr = g.host_so_base + (vaddr - elf_base);
      
      if (read_mem(host_addr, size, out)) { used_addr = host_addr; return true; }
      if (read_mem(vaddr, size, out))     { used_addr = vaddr;     return true; }
      return false;
    } else {
     
#if DEVPORT(LINUX)
      if (read_host_mem_ptrace(vaddr, size, out)) { used_addr = vaddr; return true; }
#endif
    
      if (read_mem(vaddr, size, out)) { used_addr = vaddr; return true; }
      return false;
    }
  }

  if (read_mem(vaddr, size, out)) { used_addr = vaddr; return true; }
  return false;
}

} // namespace zdb

// =============================
// Command implementations (backend-side)
// =============================
namespace {
struct WatchItemBackend {
    std::string name;
    size_t      size = 8;
    bool        is_global = true;
    uint64_t    addr = 0;
    std::vector<uint8_t> last;
    bool        is_reg = false;
    int         regnum = -1;
};
static std::unordered_map<std::string, WatchItemBackend> s_watches_backend;

static void print_value_hex_backend(const std::string& name, uint64_t addr, const std::vector<uint8_t>& v){
    std::printf("%s @0x%llx = ", name.c_str(), (unsigned long long)addr);
    if (v.empty()) { std::puts("<empty>"); return; }
    if (v.size()==8) {
        uint64_t u = 0; for (size_t i=0;i<8;++i) u |= (uint64_t)v[i] << (8*i);
        std::printf("%llu (0x%llx)\n", (unsigned long long)u, (unsigned long long)u);
        return;
    }
    if (v.size()==4) {
        uint32_t u = 0; for (size_t i=0;i<4;++i) u |= (uint32_t)v[i] << (8*i);
        std::printf("%u (0x%llx)\n", (unsigned)u, (unsigned long long)u);
        return;
    }
    for (size_t i=0;i<v.size();++i) std::printf("%02x", v[i]);
    std::puts("");
}
} // anon

namespace zdb {

void cmd_symbols_backend(){
    auto all = elfx::all_symbols();
    if (all.empty()) { std::puts("No symbols (load ELF first). "); return; }
    std::puts("Name                                      Address");
    std::puts("-------------------------------------------------");
    for (auto& p : all) {
        std::printf("%-40s  0x%016llx\n", p.first.c_str(), (unsigned long long)p.second);
    }
}

void cmd_print_var_backend(const std::string& name, size_t size){
    if (name.empty()) { std::puts("usage: print <name> [size] "); return; }
    if (size==0) size = 8;
    VarInfoSimple info;
    if (!var_resolve(name, info)) {
        uint64_t pc = show_pc();
        uint64_t elf_pc = pc;
        if (!elfx::is_riscv_elf() && g.host_attached && g.host_so_base &&
            pc >= g.host_so_base && pc < g.host_so_end) {
            uint64_t elf_base = elfx::next_addr(0);
            if (elf_base) elf_pc = elf_base + (pc - g.host_so_base);
        }
        auto sl = elfx::addr_to_source(elf_pc);
        std::printf("PRINT FAIL (symbol not found) — func='%s' line=%d\n",
                    sl.func.c_str(), sl.line);
        std::puts("hint: ensure DWARF tools available (objdump/addr2line), and build with -g -O0 -fno-omit-frame-pointer");
        return;
    }
    std::vector<uint8_t> v; uint64_t used = 0;
    if (!var_read_best_addr(info, size, used, v)) { std::puts("READ FAIL"); return; }
    if (info.is_reg) {
        std::printf("%s @REG%d = ", name.c_str(), info.regnum);
        for (size_t i=0;i<v.size();++i) std::printf("%02x", v[i]);
        std::puts("");
        return;
    }
    print_value_hex_backend(name, used, v);
}

void cmd_watch_add_backend(const std::string& name, size_t size){
    if (name.empty()) { std::puts("usage: watch add <name> [size]"); return; }
    if (size==0) size = 8;
    VarInfoSimple info;
    if (!var_resolve(name, info)) {
        uint64_t pc = show_pc();
        auto sl = elfx::addr_to_source(pc);
        std::printf("WATCH ADD FAIL (symbol not found) — func='%s' line=%d\n",
                    sl.func.c_str(), sl.line);
        std::puts("hint: ensure DWARF tools available (objdump/addr2line), and build with -g -O0 -fno-omit-frame-pointer");
        return;
    }
    WatchItemBackend w; w.name=name; w.size=size; w.is_global=info.is_global;
    if (info.is_reg) {
        std::vector<uint8_t> v; uint64_t used = 0;
        if (!var_read_best_addr(info, size, used, v)) { std::puts("WATCH ADD FAIL (REG READ)"); return; }
        w.is_reg = true; w.regnum = info.regnum; w.addr = 0; w.last = v;
        s_watches_backend[name] = w;
        std::printf("WATCH ADD '%s' [REG%d] size=%zu\n", name.c_str(), info.regnum, size);
        return;
    }
    w.addr = info.addr; std::vector<uint8_t> v; uint64_t used = info.addr;
    if (var_read_best_addr(info, size, used, v)) { w.addr = used; w.last = v; }
    s_watches_backend[name] = w;
    std::printf("WATCH ADD '%s' @0x%llx size=%zu\n", name.c_str(), (unsigned long long)s_watches_backend[name].addr, size);
}

void cmd_watch_del_backend(const std::string& name){
    if (name.empty()) { std::puts("usage: watch del <name>"); return; }
    auto it = s_watches_backend.find(name);
    if (it == s_watches_backend.end()) { std::puts("WATCH DEL FAIL (not found)"); return; }
    s_watches_backend.erase(it);
    std::printf("WATCH DEL '%s'\n", name.c_str());
}

void cmd_watch_ls_backend(){
    if (s_watches_backend.empty()) { std::puts("No watches."); return; }
    std::puts("Watches:");
    for (const auto& kv : s_watches_backend) {
        const auto& w = kv.second;
        std::printf("  %-24s @0x%llx size=%zu\n", w.name.c_str(), (unsigned long long)w.addr, w.size);
    }
}

void cmd_watch_poll_backend(){
    for (auto& kv : s_watches_backend) {
        auto& w = kv.second;
        std::vector<uint8_t> v;
        if (w.is_reg) {
            VarInfoSimple info; info.is_global=false; info.is_reg=true; info.regnum=w.regnum; info.addr=0;
            uint64_t used=0; if (!var_read_best_addr(info, w.size, used, v)) { std::printf("watch '%s': READ FAIL\n", w.name.c_str()); continue; }
            if (v != w.last) {
                std::printf("watch '%s': changed -> ", w.name.c_str());
                for (size_t i=0;i<v.size();++i) std::printf("%02x", v[i]);
                std::puts("");
                w.last = v;
            }
            continue;
        }
        VarInfoSimple info;
        if (!var_resolve(w.name, info)) { std::printf("watch '%s': RESOLVE FAIL\n", w.name.c_str()); continue; }
        uint64_t used = info.addr;
        if (!var_read_best_addr(info, w.size, used, v)) { std::printf("watch '%s': READ FAIL\n", w.name.c_str()); continue; }
        w.addr = used; w.is_global = info.is_global;
        if (v != w.last) {
            std::printf("watch '%s': changed -> ", w.name.c_str());
            print_value_hex_backend(w.name, w.addr, v);
            w.last = v;
        }
    }
}

} // namespace zdb


namespace zdb {
static bool get_child_pc(int pid, uint64_t& out_pc);
}
namespace {

using zdb::g;
// Driver state (mock-only; non-null sentinel enables driver-path logging)
static void* s_ccg = nullptr;
static uint32_t s_global_csu_id = MAKE_CSU_ID(0, 0, 0);
// Test-only: force driver path via env var (backed by mock memory)
static bool s_force_driver_stub = false;
// Remember last load parameters to support reload
static uint64_t s_last_itcm_addr = 0x10000ULL;
static uint64_t s_last_dtcm_addr = 0x1A0000ULL;
static std::string s_last_itcm_path;
static std::string s_last_dtcm_path;
static uint64_t s_last_boot_addr = 0ULL;
enum class LastLoadKind { None, Bins, Elf };
static LastLoadKind s_last_kind = LastLoadKind::None;

static inline bool in_range_u64(uint64_t a, uint64_t base, uint64_t size) {
  // Avoid always-true comparisons like (a >= 0) by using subtraction.
  // For unsigned arithmetic, if a < base, (a - base) underflows to a large value
  // and will not be < size, which is the desired false.
  return size != 0 && (a - base) < size;
}

static inline bool is_sram_addr(uint64_t /*addr*/) { return false; }

static inline bool driver_read64(uint64_t addr, uint64_t& val) {
  // Standalone: always emulate via mock DRAM
  uint64_t tmp = 0;
  if (addr >= g.dram.size()) { val = 0; return false; }
  size_t avail = g.dram.size() - static_cast<size_t>(addr);
  size_t copy = std::min(sizeof(uint64_t), avail);
  std::memcpy(&tmp, &g.dram[static_cast<size_t>(addr)], copy);
  val = tmp;
  return true;
}

static inline bool driver_write64(uint64_t addr, uint64_t val) {
  // Standalone: always emulate via mock DRAM
  if (addr >= g.dram.size()) return false;
  size_t avail = g.dram.size() - static_cast<size_t>(addr);
  size_t copy = std::min(sizeof(uint64_t), avail);
  std::memcpy(&g.dram[static_cast<size_t>(addr)], &val, copy);
  return true;
}
static inline void dump_to_dram(std::vector<uint8_t>& src, uint64_t base, unsigned start, unsigned count){
  const size_t reg_sz = 64;
  const size_t src_off = static_cast<size_t>(start) * reg_sz;
  size_t total = static_cast<size_t>(count) * reg_sz;


  if (src_off > src.size()) return;
  total = std::min(total, src.size() - src_off);
  if (base >= g.dram.size()) return;
  total = std::min(total, g.dram.size() - static_cast<size_t>(base));

  std::memcpy(&g.dram[base], &src[src_off], total);
}

static inline void clear_bp_all() {
  g.bp_by_id.clear();
  g.bp_id_by_addr.clear();
  g.next_bp_id = 1;
}

} // anon
static bool read_all(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    out.assign((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    return true;
}
static inline void ensure_size(std::vector<uint8_t>& buf, size_t need) {
    if (buf.size() < need) buf.resize(need, 0);
}
static inline bool ends_with(const std::string& s, const char* suf){
    size_t n = std::strlen(suf); return s.size()>=n && s.compare(s.size()-n,n,suf)==0;
}



// Resolve a relative file path against the directory of the running executable.
// If the original path exists or is absolute, return it as-is. Otherwise, try exe_dir/path.
static std::filesystem::path get_exe_dir() {
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf)-1);
    if (n > 0) {
        buf[n] = '\0';
        std::filesystem::path p(buf);
        return p.parent_path();
    }
    std::error_code ec;
    auto cwd = std::filesystem::current_path(ec);
    return ec ? std::filesystem::path(".") : cwd;
}

// Locate the top-level build directory (sibling of 'source') starting from exe dir.
// Fallback to exe dir if not found.
static std::filesystem::path get_top_build_dir() {
    std::error_code ec;
    auto ed = get_exe_dir();
    // First, walk up to find a directory literally named "build"
    {
        auto p = ed;
        for (int i = 0; i < 8 && !p.empty(); ++i) {
            if (p.filename() == "build") return p;
            p = p.parent_path();
        }
    }
    // Next, at each ancestor, prefer a sibling named 'build'
    {
        auto p = ed;
        for (int i = 0; i < 8 && !p.empty(); ++i) {
            auto parent = p.parent_path();
            if (parent.empty()) break;
            auto cand = parent / "build";
            if (std::filesystem::exists(cand, ec)) return cand;
            p = parent;
        }
    }
    // Fallback: current working directory may be inside build tree
    {
        auto cwd = std::filesystem::current_path(ec);
        if (!ec) {
            auto p = cwd;
            for (int i = 0; i < 8 && !p.empty(); ++i) {
                if (p.filename() == "build") return p;
                auto parent = p.parent_path();
                auto cand = parent / "build";
                if (std::filesystem::exists(cand, ec)) return cand;
                p = parent;
            }
        }
    }
    return ed; // fallback
}

static std::string resolve_with_exe_dir(const std::string& path) {
    std::filesystem::path p(path);
    std::error_code ec;
    if (p.is_absolute()) return path;
    if (std::filesystem::exists(p, ec)) return path;
    auto cand = get_exe_dir() / p;
    if (std::filesystem::exists(cand, ec)) return cand.string();
    return path;
}

namespace zdb {

static inline bool finish_after_load(bool ok, bool wakeup) {
    if (!ok) { g.running = false; g.halted = true; g.reason = "load-fail"; return false; }
    if (wakeup) { g.running = true; g.halted = false; g.reason.clear(); }
    else        { g.running = false; g.halted = true;  g.reason = "halt"; }
    return true;
}

// Test helper: enable driver-path stub regardless of real driver availability.
void enable_driver_stub() {
  // Mark stub enabled and ensure non-null s_ccg so read/write go through driver path
  s_force_driver_stub = true;
  if (!s_ccg) s_ccg = reinterpret_cast<void*>(0x1);
  std::puts("[DRIVER] test stub active (forcing driver path)");
}

bool init(unsigned csu_id){
  (void)csu_id;
  g.id = 0; g.running=false; g.halted=true; g.pc=0; g.reason="init";
  g.itcm.resize(128*1024); g.dtcm.resize(2*1024*1024); g.dram.resize(8*1024*1024);
  g.scalar.assign(32, 0);
  g.vregs.resize(64*64); g.cregs.resize(64*64);
  for (size_t i=0;i<g.scalar.size();++i) g.scalar[i]=0x1000+i;
  for (size_t i=0;i<g.vregs.size();++i) g.vregs[i]=(uint8_t)(i&0xFF);
  for (size_t i=0;i<g.cregs.size();++i) g.cregs[i]=(uint8_t)((i*3)&0xFF);
  clear_bp_all();
  g.mbox = {}; 
  // Clear last-load state to avoid cross-test/session contamination
  s_last_kind = LastLoadKind::None;
  s_last_itcm_addr = 0x10000ULL;
  s_last_dtcm_addr = 0x1A0000ULL;
  s_last_itcm_path.clear();
  s_last_dtcm_path.clear();
  s_last_boot_addr = 0ULL;
  g.loaded_elf_path.clear();
  g.host_so_base = 0;
  g.host_so_end = 0;
  // Check env to force driver path even without real driver
  if (!s_force_driver_stub) {
    const char* force = std::getenv("ZDB_FORCE_DRIVER");
    if (force && (std::strcmp(force, "1") == 0 || std::strcmp(force, "true") == 0)) {
      s_force_driver_stub = true;
      // Set a non-null sentinel so read/write path logs as driver
      if (!s_ccg) s_ccg = reinterpret_cast<void*>(0x1);
      std::puts("[DRIVER] test stub active (forcing driver path)");
    }
  }
  // Standalone: no real driver; leave s_ccg as sentinel when stub enabled
  s_global_csu_id = MAKE_CSU_ID(0, 0, (int)csu_id);
  return true;
}

void shutdown(){
  s_ccg = nullptr;
  s_force_driver_stub = false;
}
bool reload() {
  // Reload the most recently loaded artifact
  switch (s_last_kind) {
    case LastLoadKind::Elf:
      if (!g.loaded_elf_path.empty()) {
        std::printf("[MOCK] reload ELF: '%s'\n", g.loaded_elf_path.c_str());
        return hex_load_elf(g.loaded_elf_path, s_last_itcm_addr, s_last_dtcm_addr, /*wakeup*/false);
      }
      break;
    case LastLoadKind::Bins:
      if (!s_last_itcm_path.empty() && !s_last_dtcm_path.empty()) {
        std::printf("[MOCK] reload BINs: itcm='%s', dtcm='%s'\n",
                    s_last_itcm_path.c_str(), s_last_dtcm_path.c_str());
        return hex_load(s_last_itcm_path, s_last_dtcm_path,
                        s_last_itcm_addr, s_last_dtcm_addr,
                        /*wakeup*/false, s_last_boot_addr);
      }
      break;
    case LastLoadKind::None:
      break;
  }
  std::puts("[MOCK] reload FAIL: no previous executable or bins recorded");
  return false;
}


void reset() {
 
  bool ok = init(g.id);
  (void)ok;
  g.reason = "reset";
}

bool hex_load(const std::string& itcm_bin_path,
                   const std::string& dtcm_bin_path,
                   uint64_t itcm_addr,
                   uint64_t dtcm_addr,
                   bool wakeup,
                   uint64_t boot_addr) 
{
    // Try original path; if not found and relative, try resolving against exe dir.
    const std::string itcm_path = resolve_with_exe_dir(itcm_bin_path);
    const std::string dtcm_path = resolve_with_exe_dir(dtcm_bin_path);

    std::vector<uint8_t> itcm_bin, dtcm_bin;
    if (!read_all(itcm_path, itcm_bin)) {
        std::printf("LOAD FAIL: cannot open/read ITCM file: %s\n", itcm_bin_path.c_str());
        return finish_after_load(false, /*wakeup ignored*/false);
    }
    if (!read_all(dtcm_path, dtcm_bin)) {
        std::printf("LOAD FAIL: cannot open/read DTCM file: %s\n", dtcm_bin_path.c_str());
        return finish_after_load(false, /*wakeup ignored*/false);
    }

  
    const size_t itcm_size = g.itcm.size();
    const size_t dtcm_size = g.dtcm.size();
    if (itcm_addr > itcm_size ||
        itcm_bin.size() > itcm_size - static_cast<size_t>(itcm_addr)) {
        std::printf("LOAD FAIL: ITCM write overflow: addr 0x%llx + %zu > %zu\n",
                    (unsigned long long)itcm_addr, itcm_bin.size(), itcm_size);
        return finish_after_load(false, /*wakeup ignored*/false);
    }
    if (dtcm_addr > dtcm_size ||
        dtcm_bin.size() > dtcm_size - static_cast<size_t>(dtcm_addr)) {
        std::printf("LOAD FAIL: DTCM write overflow: addr 0x%llx + %zu > %zu\n",
                    (unsigned long long)dtcm_addr, dtcm_bin.size(), dtcm_size);
        return finish_after_load(false, /*wakeup ignored*/false);
    }

   
    std::memcpy(&g.itcm[static_cast<size_t>(itcm_addr)], itcm_bin.data(), itcm_bin.size());
    std::memcpy(&g.dtcm[static_cast<size_t>(dtcm_addr)], dtcm_bin.data(), dtcm_bin.size());

   
    if (boot_addr != 0) {
        g.pc = boot_addr;
    } else {
        
        std::puts("LOAD WARN (bins): boot address not provided, PC unchanged.");
    }

    std::printf("LOAD OK (bins): ITCM '%s' -> itcm[+0x%llx], bytes=%zu; "
                "DTCM '%s' -> dtcm[+0x%llx], bytes=%zu; PC=0x%llx\n",
                itcm_path.c_str(), (unsigned long long)itcm_addr, itcm_bin.size(),
                dtcm_path.c_str(), (unsigned long long)dtcm_addr, dtcm_bin.size(),
                (unsigned long long)g.pc);

    // Record last load parameters for reload
    s_last_itcm_path = itcm_path;
    s_last_dtcm_path = dtcm_path;
    s_last_itcm_addr = itcm_addr;
    s_last_dtcm_addr = dtcm_addr;
    s_last_boot_addr = boot_addr;
    s_last_kind = LastLoadKind::Bins;
    // Clear any previous ELF context when loading BINs
    g.loaded_elf_path.clear();
    g.host_so_base = 0;
    g.host_so_end = 0;

    return finish_after_load(true, wakeup);
}
bool hex_load_elf(const std::string& elf_path,
                  uint64_t itcm_addr,
                  uint64_t dtcm_addr,
                  bool wakeup)
{
    // Resolve ELF path similarly: try provided path, else exe-dir fallback.
    const std::string resolved_elf = resolve_with_exe_dir(elf_path);
    std::ifstream test(resolved_elf);
    if (!test.good()) {
        std::printf("LOAD FAIL: cannot open ELF file: %s\n", elf_path.c_str());
        std::error_code ec;
        auto cwd = std::filesystem::current_path(ec);
        if (!ec) {
            std::printf("Current working directory: %s\n", cwd.string().c_str());
        }
        auto ed = get_exe_dir();
        std::printf("Executable directory: %s\n", ed.string().c_str());
        return finish_after_load(false, false);
    }


    // Support both device-side ELF and host-side executable produced by sim/ (with custom sections)
    std::vector<std::string> ITCM_SECS = {".text", ".itcm", ".itcm.", ".text.itcm"};
    std::vector<std::string> DTCM_SECS = {".data", ".sdata", ".rodata", ".dtcm", ".dtcm.", ".dtcm.ro", ".dtcm.data"};

    elfx::BinImage inst_img, data_img;
  if (!elfx::build_bins_and_indices(resolved_elf, ITCM_SECS, DTCM_SECS,
                                      inst_img, data_img, get_top_build_dir().string(), true)) {
        std::puts("LOAD FAIL: ELF parse/build failed");
        return finish_after_load(false, wakeup);
    }


    const size_t itcm_size = g.itcm.size();
    const size_t dtcm_size = g.dtcm.size();

    if (inst_img.size > 0 &&
        (itcm_addr > itcm_size || inst_img.size > itcm_size - (size_t)itcm_addr)) {
        std::printf("LOAD FAIL: ITCM overflow: addr 0x%llx + %llu > %zu\n",
                    (unsigned long long)itcm_addr,
                    (unsigned long long)inst_img.size,
                    itcm_size);
        return finish_after_load(false, wakeup);
    }
    if (data_img.size > 0 &&
        (dtcm_addr > dtcm_size || data_img.size > dtcm_size - (size_t)dtcm_addr)) {
        std::printf("LOAD FAIL: DTCM overflow: addr 0x%llx + %llu > %zu\n",
                    (unsigned long long)dtcm_addr,
                    (unsigned long long)data_img.size,
                    dtcm_size);
        return finish_after_load(false, wakeup);
    }


    if (inst_img.size > 0) {
        std::vector<uint8_t> bin;
        if (!read_all(inst_img.path, bin)) {
            std::printf("LOAD FAIL: cannot read %s\n", inst_img.path.c_str());
            return finish_after_load(false, wakeup);
        }
        std::memcpy(&g.itcm[(size_t)itcm_addr], bin.data(), bin.size());
    }

    if (data_img.size > 0) {
        std::vector<uint8_t> bin;
        if (!read_all(data_img.path, bin)) {
            std::printf("LOAD FAIL: cannot read %s\n", data_img.path.c_str());
            return finish_after_load(false, wakeup);
        }
        std::memcpy(&g.dtcm[(size_t)dtcm_addr], bin.data(), bin.size());
    }

    
  uint64_t pc = 0, sym = 0;
  // Choose a better entry PC depending on ELF type.
  if (!elfx::is_riscv_elf()) {
    // Host executable: prefer explicit test entry or main-like symbols, else first disasm address.
    uint64_t sym_sim_entry = 0, sym_main = 0;
    if (elfx::sym_lookup("sim_entry", sym_sim_entry)) pc = sym_sim_entry;
    else if (elfx::sym_lookup("main", sym_main)) pc = sym_main;
    else if (elfx::sym_lookup("mat_add", sym)) pc = sym;
    else pc = elfx::next_addr(0);
  } else {
        // Device ELF: keep prior behavior.
        if (elfx::sym_lookup("_start", sym)) pc = sym;
        else if (elfx::sym_lookup("main", sym)) pc = sym;
        else if (inst_img.size > 0) pc = inst_img.base;
        else if (data_img.size > 0) pc = data_img.base;
        else pc = itcm_addr; // fallback
    }

  g.pc = pc;
  // Record loaded ELF path for host relocation; clear any previous host image mapping
  g.loaded_elf_path = resolved_elf;
  g.host_so_base = 0;
  g.host_so_end = 0;
  // Record last load addresses for reload
  s_last_itcm_addr = itcm_addr;
  s_last_dtcm_addr = dtcm_addr;
  s_last_kind = LastLoadKind::Elf;


    std::printf("LOAD OK (ELF): '%s'\n", resolved_elf.c_str());
    std::printf("  ITCM <- %s (size=%llu, base=0x%llx)\n",
                inst_img.path.c_str(),
                (unsigned long long)inst_img.size,
                (unsigned long long)itcm_addr);
    std::printf("  DTCM <- %s (size=%llu, base=0x%llx)\n",
                data_img.path.c_str(),
                (unsigned long long)data_img.size,
                (unsigned long long)dtcm_addr);
  std::printf("  Entry PC = 0x%llx\n", (unsigned long long)pc);
  if (!elfx::is_riscv_elf()) {
    uint64_t a=0; 
    if (elfx::sym_lookup("sim_entry", a)) std::printf("  sym sim_entry = 0x%llx\n", (unsigned long long)a);
    if (elfx::sym_lookup("main", a))      std::printf("  sym main      = 0x%llx\n", (unsigned long long)a);
  }

    return finish_after_load(true, wakeup);
}



void halt(){ g.halted=true; g.running=false; g.reason="user"; }
void cont(){
  // Run-forward until we hit an enabled breakpoint, or finish (end-of-image),
  // or until a step budget is exhausted (only when breakpoints exist).
  // This makes 'cont' behave like typical debuggers: execution continues
  // and stops on bp; when there is no breakpoint, it runs to completion.

  // Default budget when breakpoints exist: 1,000,000 steps.
  // Can be overridden by env ZDB_CONT_BUDGET (decimal or 0x..).
  unsigned long long budget = 1000000ULL;
  if (const char* s = std::getenv("ZDB_CONT_BUDGET")) {
    errno = 0; char* endp = nullptr;
    unsigned long long v = std::strtoull(s, &endp, 0);
    if (errno == 0 && endp && endp != s && v > 0) budget = v;
  }

  g.halted = false;
  g.running = true;
  g.reason.clear();
  if (!elfx::is_riscv_elf()) {
    if (!g.host_attached) {
      std::printf("[CONT] target is not running; please run first\n");
      g.halted = true; g.running = false; g.reason = "not-attached";
      return;
    }
   
    errno = 0;
    if (kill(g.host_pid, 0) != 0 && errno == ESRCH) {
     
      g.host_attached = false; g.host_pid = -1;
      g.halted = true; g.running = false; g.reason = "program-end";
      std::printf("[CONT] program already finished; please run to restart\n");
      return;
    }
   
    if (g.host_so_base == 0 && !g.loaded_elf_path.empty()) {
      uint64_t b=0, e=0;
      if (find_image_base_in_maps(g.host_pid, g.loaded_elf_path, b, e)) {
        g.host_so_base = b; g.host_so_end = e;
      }
    }
   
    unsigned bp_id = 0; uint64_t bp_vaddr = 0;
    for (const auto& kv : g.bp_by_id) {
      if (kv.second.enabled) { bp_id = kv.first; bp_vaddr = kv.second.addr; break; }
    }
    if (bp_id) {
      uint64_t vaddr_base = elfx::next_addr(0);
      uint64_t target_rt = 0;
      if (vaddr_base && bp_vaddr >= vaddr_base && g.host_so_base) {
        target_rt = g.host_so_base + (bp_vaddr - vaddr_base);
      }
      if (!(target_rt >= g.host_so_base && target_rt < g.host_so_end)) {
        g.halted = true; g.running = false; g.reason = "bp-unmapped";
        std::printf("[CONT] breakpoint address unmapped; cannot continue to breakpoint\n");
        return;
      }
      uint64_t hit_pc = 0;
      if (!run_to_addr_with_int3(g.host_pid, target_rt, hit_pc)) {
        g.halted = true; g.running = false; g.reason = "run-to-failed";
        return;
      }
      g.pc = hit_pc;
      g.halted = true; g.running = false; g.reason = "breakpoint";
      return;
    }
    
    while (true) {
      if (ptrace(PTRACE_CONT, g.host_pid, 0, 0) != 0) {
        if (errno == ESRCH) {
          g.host_attached = false; g.host_pid = -1;
          g.halted = true; g.running = false; g.reason = "program-end";
          return;
        }
       
        g.halted = true; g.running = false; g.reason = "cont-fail";
        return;
      }
      int status = 0;
      if (waitpid(g.host_pid, &status, 0) < 0) {
        if (errno == ESRCH) {
          g.host_attached = false; g.host_pid = -1;
          g.halted = true; g.running = false; g.reason = "program-end";
          return;
        }
        g.halted = true; g.running = false; g.reason = "wait-fail";
        return;
      }
      if (WIFEXITED(status) || WIFSIGNALED(status)) {
        g.host_attached = false; g.host_pid = -1;
        g.halted = true; g.running = false; g.reason = "program-end";
        return;
      }
      if (WIFSTOPPED(status)) {
      
        continue;
      }
    }
  }

  // Detect whether there is any enabled breakpoint; if none, we will run
  // without a budget until 'next_addr' cannot advance (program end).
  bool has_enabled_bp = false;
  for (const auto& kv : g.bp_by_id) {
    if (kv.second.enabled) { has_enabled_bp = true; break; }
  }

  bool hit = false;
  bool finished = false;

  auto one_step_and_check = [&]() -> bool {
    uint64_t next = elfx::next_addr(g.pc);
    if (next == g.pc) { finished = true; return false; }
    g.pc = next;

    // Check direct runtime-address breakpoints
    auto itbp = g.bp_id_by_addr.find(g.pc);
    if (itbp != g.bp_id_by_addr.end()) {
      unsigned id = itbp->second;
      auto jt = g.bp_by_id.find(id);
      if (jt != g.bp_by_id.end() && jt->second.enabled) { hit = true; return false; }
    }

    // For host-attached executables, also match relocated ELF-virtual-address breakpoints
    if (!hit && !elfx::is_riscv_elf() && g.host_attached && g.host_so_base && g.pc >= g.host_so_base && g.pc < g.host_so_end) {
      uint64_t elf_vaddr_base = elfx::next_addr(0);
      uint64_t reloc_pc = g.pc - g.host_so_base + elf_vaddr_base;
      auto it2 = g.bp_id_by_addr.find(reloc_pc);
      if (it2 != g.bp_id_by_addr.end()) {
        unsigned id2 = it2->second;
        auto jt2 = g.bp_by_id.find(id2);
        if (jt2 != g.bp_by_id.end() && jt2->second.enabled) { hit = true; return false; }
      }
    }
    return true; // continue
  };

  if (has_enabled_bp) {
    while (budget--) {
      if (!one_step_and_check()) break;
    }
  } else {
    // No breakpoint: run to program end (no budget limit)
    while (true) {
      if (!one_step_and_check()) break;
    }
  }

  g.halted = true;
  g.running = false;
  if (hit) {
    g.reason = "breakpoint";
  } else if (finished) {
    g.reason = "program-end"; // ran to completion
  } else {
    g.reason = "cont-budget-exhausted"; // user can increase budget or set bp closer
  }
}

// run(): In host-mode, restart the target process each time and run to the first enabled breakpoint;
// in device-mode, behaves like cont.
void run(){
  g.halted = false; g.running = true; g.reason.clear();
  if (!elfx::is_riscv_elf()) {
    if (g.host_attached) {
      int pid = g.host_pid;
      (void)ptrace(PTRACE_DETACH, pid, 0, 0);
      errno = 0;
      if (kill(pid, 0) == 0) {
        (void)kill(pid, SIGKILL);
        int st = 0; (void)waitpid(pid, &st, WNOHANG);
      }
      g.host_attached = false; g.host_pid = -1;
    } else if (g.host_pid > 0) {
      errno = 0; if (kill(g.host_pid, 0) != 0 && errno == ESRCH) { g.host_pid = -1; }
    }
    g.host_so_base = 0; g.host_so_end = 0;

    unsigned bp_id = 0; uint64_t bp_vaddr = 0;
    for (const auto& kv : g.bp_by_id) {
      if (kv.second.enabled) { bp_id = kv.first; bp_vaddr = kv.second.addr; break; }
    }
    bool ok=false;
    if (!g.loaded_elf_path.empty()) { ok = host_attach_exe(g.loaded_elf_path, {}); }
    if (!ok) {
      std::printf("[RUN] host attach failed; cannot run. Ensure ELF is loaded and executable exists.\n");
      g.halted = true; g.running = false; g.reason = "attach-fail";
      return;
    }
    if (g.host_so_base == 0 && !g.loaded_elf_path.empty()) {
      uint64_t b=0,e=0;
      if (find_image_base_in_maps(g.host_pid, g.loaded_elf_path, b, e)) {
        g.host_so_base = b; g.host_so_end = e;
      } else {
        std::printf("[RUN] image map not found; cannot compute breakpoint runtime address\n");
        g.halted = true; g.running = false; g.reason = "map-missing";
        return;
      }
    }
    if (bp_id != 0) {
      uint64_t vaddr_base = elfx::next_addr(0);
      uint64_t target_rt = 0;
      if (vaddr_base && bp_vaddr >= vaddr_base) {
        target_rt = g.host_so_base + (bp_vaddr - vaddr_base);
      }
      if (!(target_rt >= g.host_so_base && target_rt < g.host_so_end)) {
        std::printf("[RUN] bp runtime addr not within image map; cannot run-to breakpoint\n");
        g.halted = true; g.running = false; g.reason = "bp-unmapped";
        return;
      }
      uint64_t hit_pc = 0;
      if (!run_to_addr_with_int3(g.host_pid, target_rt, hit_pc)) {
        g.halted = true; g.running = false; g.reason = "run-to-failed";
        return;
      }
      g.pc = hit_pc;
      g.halted = true; g.running = false; g.reason = "breakpoint";
      return;
    } else {
      while (true) {
        if (ptrace(PTRACE_CONT, g.host_pid, 0, 0) != 0) {
          if (errno == ESRCH) {
            g.host_attached = false; g.host_pid = -1;
            g.halted = true; g.running = false; g.reason = "program-end";
            return;
          }
          g.halted = true; g.running = false; g.reason = "cont-fail";
          return;
        }
        int status = 0;
        if (waitpid(g.host_pid, &status, 0) < 0) {
          if (errno == ESRCH) {
            g.host_attached = false; g.host_pid = -1;
            g.halted = true; g.running = false; g.reason = "program-end";
            return;
          }
          g.halted = true; g.running = false; g.reason = "wait-fail";
          return;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
          g.host_attached = false; g.host_pid = -1;
          g.halted = true; g.running = false; g.reason = "program-end";
          return;
        }
        if (WIFSTOPPED(status)) {
          continue;
        }
      }
    }
  }
  cont();
}

void step(unsigned n){
  if (!g.halted) halt();
  while (n--) {
    uint64_t next = elfx::next_addr(g.pc);
    if (next == g.pc) break; 
    g.pc = next;

    bool hit = false;
 
    if (!hit) {
      auto itbp = g.bp_id_by_addr.find(g.pc);
      if (itbp != g.bp_id_by_addr.end()) {
        unsigned id = itbp->second;
        auto jt = g.bp_by_id.find(id);
        if (jt != g.bp_by_id.end() && jt->second.enabled) hit = true;
      }
    }
   
    if (!hit && !elfx::is_riscv_elf() && g.host_attached && g.host_so_base && g.pc >= g.host_so_base && g.pc < g.host_so_end) {
      uint64_t elf_vaddr_base = elfx::next_addr(0);
      uint64_t reloc_pc = g.pc - g.host_so_base + elf_vaddr_base;
      auto it2 = g.bp_id_by_addr.find(reloc_pc);
      if (it2 != g.bp_id_by_addr.end()) {
        unsigned id2 = it2->second;
        auto jt2 = g.bp_by_id.find(id2);
        if (jt2 != g.bp_by_id.end() && jt2->second.enabled) hit = true;
      }
    }

    if (hit) { g.halted = true; g.running = false; g.reason = "breakpoint"; break; }
  }
}
void stepl(unsigned n){
  if (!g.halted) halt();
  while (n--) {
    if (!elfx::is_riscv_elf() && !g.host_attached) {
      std::printf("[STEPL] target is not running; please run first\n");
      g.halted = true; g.running = false; g.reason = "not-attached";
      return;
    }
    if (!elfx::is_riscv_elf() && g.host_attached) {
      uint64_t tmp_pc = 0;
      if (!get_child_pc(g.host_pid, tmp_pc)) {
        g.halted = true; g.running = false; if (g.reason.empty()) g.reason = "not-running";
        std::printf("[STEPL] target is not running; please run first\n");
        return;
      }
    }
    std::printf("[STEPL] begin: PC=0x%llx\n", (unsigned long long)g.pc);
   
    uint64_t elf_vaddr_base = elfx::next_addr(0);
    // Resolve current PC to source location
    uint64_t src_query_pc = g.pc;
    if (!elfx::is_riscv_elf() && g.host_attached && g.host_so_base && g.pc >= g.host_so_base && g.pc < g.host_so_end) {
      // Relocate runtime PC into ELF address space: pc' = pc - load_base + vaddr_base
      src_query_pc = g.pc - g.host_so_base + elf_vaddr_base;
    }
    auto cur = elfx::addr_to_source(src_query_pc);
    if ((cur.file.empty() || cur.line <= 0) && !elfx::is_riscv_elf()) {
      // Fallback: try absolute PC in case elfx expects non-relocated address
      auto cur_abs = elfx::addr_to_source(g.pc);
      if (!cur_abs.file.empty() && cur_abs.line > 0) cur = cur_abs;
    }
    const std::string file = cur.file;
    const int line = cur.line;
    if (!file.empty() && line > 0) {
      std::printf("[STEPL] src: %s:%d\n", file.c_str(), line);
    } else {
      std::printf("[STEPL] no source mapping for PC=0x%llx\n", (unsigned long long)g.pc);
    }

    // For device ELF (RISC-V), if we cannot map current PC to a valid source line,
    // fall back to advancing by disassembly address. For host ELF, do not early-fallback;
    // we will try real single-step below.
    if (elfx::is_riscv_elf()) {
      if (file.empty() || line <= 0) {
        std::printf("[STEPL] fallback: advance to next address (no mapping)\n");
        uint64_t next = elfx::next_addr(g.pc);
        if (next == g.pc) return; // no progress possible
        g.pc = next;
        // breakpoint check
        auto itbp = g.bp_id_by_addr.find(g.pc);
        if (itbp != g.bp_id_by_addr.end()) {
          unsigned id = itbp->second;
          auto jt = g.bp_by_id.find(id);
          if (jt != g.bp_by_id.end() && jt->second.enabled) { g.halted=true; g.running=false; g.reason="breakpoint"; return; }
        }
        continue;
      }
    }

   
    {
      unsigned guard = 262144;
      unsigned steps = 0;
      std::printf("[STEPL] advance until line changes in same file\n");
      if (!elfx::is_riscv_elf()) {
       
        if (!g.host_attached) {
          std::printf("[STEPL] host not attached; please run first (e.g. 'run' or 'cont')\n");
          g.halted = true; g.running = false; g.reason = "not-attached";
          return;
        }
       
        if (g.host_so_base == 0 && !g.loaded_elf_path.empty()) {
          uint64_t b=0, e=0;
          if (find_image_base_in_maps(g.host_pid, g.loaded_elf_path, b, e)) {
            g.host_so_base = b; g.host_so_end = e;
            std::printf("[HOST] image map: base=0x%llx end=0x%llx (%s)\n",
                        (unsigned long long)b, (unsigned long long)e, g.loaded_elf_path.c_str());
          }
        }
        unsigned no_src_steps = 0;
        while (guard--) {
          bool progressed = false;
          if (g.host_attached) {
            if (!host_stepi(1)) {
           
              if (!g.host_attached) {
                g.halted = true; g.running = false; g.reason = "program-end";
                std::printf("[STEPL] target is not running; please run first\n");
              }
              return; 
            }
            progressed = true; steps++;
      
            if (g.host_so_base == 0 && !g.loaded_elf_path.empty()) {
              uint64_t b2=0, e2=0;
              if (find_image_base_in_maps(g.host_pid, g.loaded_elf_path, b2, e2)) {
                g.host_so_base = b2; g.host_so_end = e2;
                std::printf("[HOST] image map: base=0x%llx end=0x%llx (%s)\n",
                            (unsigned long long)b2, (unsigned long long)e2, g.loaded_elf_path.c_str());
              }
            }
            // If current PC is not within the chosen image range, try remapping to the exec segment containing it
            if (g.host_so_base && !(g.pc >= g.host_so_base && g.pc < g.host_so_end) && !g.loaded_elf_path.empty()) {
              uint64_t xb=0, xe=0;
              if (find_image_exec_map_for_pc(g.host_pid, g.loaded_elf_path, g.pc, xb, xe)) {
                g.host_so_base = xb; g.host_so_end = xe;
                std::printf("[HOST] remap image exec segment for PC: base=0x%llx end=0x%llx\n",
                            (unsigned long long)xb, (unsigned long long)xe);
              }
            }
            uint64_t src_now_pc = g.pc;
            if (!elfx::is_riscv_elf() && g.host_attached && g.host_so_base && g.pc >= g.host_so_base && g.pc < g.host_so_end) {
              src_now_pc = g.pc - g.host_so_base + elf_vaddr_base;
            }
            auto now = elfx::addr_to_source(src_now_pc);
            if ((now.file.empty() || now.line <= 0) && !elfx::is_riscv_elf()) {
              auto now_abs = elfx::addr_to_source(g.pc);
              if (!now_abs.file.empty() && now_abs.line > 0) now = now_abs;
            }
            if (now.file.empty() || now.line <= 0) {
         
              unsigned limit = (g.host_so_base == 0) ? 4096 : 512;
              if (++no_src_steps >= limit) { std::printf("[STEPL] no-source region; bail after %u steps\n", no_src_steps); break; }
            } else {
              no_src_steps = 0;
              if (now.file == file && now.line != line) {
                break;
              }
              if (now.file != file) { std::printf("[STEPL] left file '%s' → '%s'\n", file.c_str(), now.file.c_str()); break; }
            }
          }
          // breakpoint check
          auto itbp2 = g.bp_id_by_addr.find(g.pc);
          if (itbp2 != g.bp_id_by_addr.end()) {
            unsigned id = itbp2->second;
            auto jt = g.bp_by_id.find(id);
            if (jt != g.bp_by_id.end() && jt->second.enabled) { g.halted=true; g.running=false; g.reason="breakpoint"; return; }
          }
          // also check relocated ELF address when host-attached in image range
          if (!elfx::is_riscv_elf() && g.host_attached && g.host_so_base && g.pc >= g.host_so_base && g.pc < g.host_so_end) {
            uint64_t elf_vaddr_base = elfx::next_addr(0);
            uint64_t src_pc = g.pc - g.host_so_base + elf_vaddr_base;
            auto kt = g.bp_id_by_addr.find(src_pc);
            if (kt != g.bp_id_by_addr.end()) {
              unsigned id2 = kt->second;
              auto jt2 = g.bp_by_id.find(id2);
              if (jt2 != g.bp_by_id.end() && jt2->second.enabled) { g.halted=true; g.running=false; g.reason="breakpoint"; return; }
            }
          }
          if (!progressed) break;
        }
      } else {
      
        while (guard--) {
          uint64_t next = elfx::next_addr(g.pc);
          if (next == g.pc) break; // cannot advance further
          g.pc = next; ++steps;
          // breakpoint check
          auto itbp2 = g.bp_id_by_addr.find(g.pc);
          if (itbp2 != g.bp_id_by_addr.end()) {
            unsigned id = itbp2->second;
            auto jt = g.bp_by_id.find(id);
            if (jt != g.bp_by_id.end() && jt->second.enabled) { g.halted=true; g.running=false; g.reason="breakpoint"; return; }
          }
          auto now = elfx::addr_to_source(g.pc);
          if (!now.file.empty() && now.file == file && now.line > 0 && now.line != line) {
            break; 
          }
        }
      }
      uint64_t final_src_pc = g.pc;
      if (!elfx::is_riscv_elf() && g.host_attached && g.host_so_base && g.pc >= g.host_so_base && g.pc < g.host_so_end) {
        final_src_pc = g.pc - g.host_so_base + elf_vaddr_base;
      }
      auto now = elfx::addr_to_source(final_src_pc);
      if ((now.file.empty() || now.line <= 0) && !elfx::is_riscv_elf()) {
        auto now_abs = elfx::addr_to_source(g.pc);
        if (!now_abs.file.empty() && now_abs.line > 0) now = now_abs;
      }
      std::printf("[STEPL] stepped %u → PC=0x%llx; src: %s:%d\n",
                  steps, (unsigned long long)g.pc,
                  now.file.c_str(), now.line);
    }
  }
}
uint64_t show_pc(){ return g.pc; }

void get_status(std::string& state, uint64_t& pc, std::string& reason){
  state = g.running? "running":"halted"; pc=g.pc; reason=g.reason;
}



bool bp_set(uint64_t addr, unsigned id){
  if (addr == 0) return false;

 
  if (id == 0) id = g.next_bp_id++;

 
  auto old = g.bp_id_by_addr.find(addr);
  if (old != g.bp_id_by_addr.end()) {
 
    unsigned old_id = old->second;
    g.bp_by_id.erase(old_id);
  }

  g.bp_id_by_addr[addr] = id;
  g.bp_by_id[id] = Breakpoint{ id, addr, true };
  return true;
}

bool bp_del(unsigned id){
  auto it = g.bp_by_id.find(id);
  if (it == g.bp_by_id.end()) return false;
  uint64_t addr = it->second.addr;
  g.bp_by_id.erase(it);
  auto jt = g.bp_id_by_addr.find(addr);
  if (jt != g.bp_id_by_addr.end() && jt->second == id) g.bp_id_by_addr.erase(jt);
  return true;
}

bool bp_del_all(){
  clear_bp_all();
  return true;
}

bool bp_enable(unsigned id){
  auto it = g.bp_by_id.find(id);
  if (it == g.bp_by_id.end()) return false;
  it->second.enabled = true;
  return true;
}

bool bp_disable(unsigned id){
  auto it = g.bp_by_id.find(id);
  if (it == g.bp_by_id.end()) return false;
  it->second.enabled = false;
  return true;
}


bool bp_list(std::vector<std::tuple<unsigned, uint64_t, bool>>& out){
  out.clear();
  out.reserve(g.bp_by_id.size());
  for (const auto& kv : g.bp_by_id) {
    const auto& b = kv.second;
    out.emplace_back(b.id, b.addr, b.enabled);
  }
  std::sort(out.begin(), out.end(),
            [](auto& a, auto& b){ return std::get<0>(a) < std::get<0>(b); });
  return true;
}



void regs_scalar_print(){
  // Linux-only: when host-attached, dump native registers via ptrace
#if DEVPORT(LINUX)
  if (g.host_attached) {
    struct user_regs_struct regs{};
    if (ptrace(PTRACE_GETREGS, g.host_pid, 0, &regs) != 0) {
      std::perror("ptrace(GETREGS)");
    } else {
      // x86_64-only register dump
      std::printf("RIP = 0x%016llx\n", (unsigned long long)regs.rip);
      std::printf("RSP = 0x%016llx\n", (unsigned long long)regs.rsp);
      std::printf("RBP = 0x%016llx\n", (unsigned long long)regs.rbp);
      std::printf("RAX = 0x%016llx\n", (unsigned long long)regs.rax);
      std::printf("RBX = 0x%016llx\n", (unsigned long long)regs.rbx);
      std::printf("RCX = 0x%016llx\n", (unsigned long long)regs.rcx);
      std::printf("RDX = 0x%016llx\n", (unsigned long long)regs.rdx);
      std::printf("RSI = 0x%016llx\n", (unsigned long long)regs.rsi);
      std::printf("RDI = 0x%016llx\n", (unsigned long long)regs.rdi);
      std::printf("R8  = 0x%016llx\n", (unsigned long long)regs.r8);
      std::printf("R9  = 0x%016llx\n", (unsigned long long)regs.r9);
      std::printf("R10 = 0x%016llx\n", (unsigned long long)regs.r10);
      std::printf("R11 = 0x%016llx\n", (unsigned long long)regs.r11);
      std::printf("R12 = 0x%016llx\n", (unsigned long long)regs.r12);
      std::printf("R13 = 0x%016llx\n", (unsigned long long)regs.r13);
      std::printf("R14 = 0x%016llx\n", (unsigned long long)regs.r14);
      std::printf("R15 = 0x%016llx\n", (unsigned long long)regs.r15);
    }
    return;
  }
#endif
  for (size_t i=0;i<g.scalar.size();++i)
    std::printf("x%-2zu = 0x%016llx\n", i, (unsigned long long)g.scalar[i]);
}

bool probe_vec(unsigned start, unsigned count, uint64_t& dump_addr){
  g.mbox.cmd=1; g.mbox.status=1; // BUSY
  dump_addr = g.mbox.buf_addr = 0x200000;
  g.mbox.count = count;
  dump_to_dram(g.vregs, g.mbox.buf_addr, start, count);
  g.mbox.status=2; // DONE
  std::printf("probe vec DONE @0x%llx count=%u\n",
              (unsigned long long)dump_addr, count);
  return true;
}

bool probe_const(unsigned start, unsigned count, uint64_t& dump_addr){
  g.mbox.cmd=2; g.mbox.status=1;
  dump_addr = g.mbox.buf_addr = 0x210000;
  g.mbox.count = count;
  dump_to_dram(g.cregs, g.mbox.buf_addr, start, count);
  g.mbox.status=2;
  std::printf("probe const DONE @0x%llx count=%u\n",
              (unsigned long long)dump_addr, count);
  return true;
}

bool read_mem(uint64_t addr, size_t size, std::vector<uint8_t>& out){
  // Host-attached: only use ptrace when address lies inside mapped executable range.
  if (g.host_attached) {
    bool in_host_map = (g.host_so_base && g.host_so_end &&
                        addr >= g.host_so_base && (addr + size) <= g.host_so_end);
    if (in_host_map) {
      std::printf("[MEM] READ via host-ptrace pid=%d addr=0x%llx size=%zu\n",
                  g.host_pid, (unsigned long long)addr, size);
      out.resize(size);
      size_t i = 0;
      while (i < size) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, g.host_pid, (void*)(addr + i), 0);
        if (word == -1 && errno != 0) { std::perror("ptrace(PEEKDATA)"); return false; }
        size_t copy = std::min(size - i, sizeof(long));
        std::memcpy(&out[i], &word, copy);
        i += copy;
      }
      return true;
    }
    // Not in host mapping: fall through to driver/mock path below.
  }
  // Otherwise, use driver-host APIs to read device memory if available
  if (s_ccg) {
    std::printf("[MEM] READ via driver (%s) addr=0x%llx size=%zu\n",
                is_sram_addr(addr) ? "SRAM" : "DRAM",
                (unsigned long long)addr, size);
    out.resize(size);
    size_t i = 0;
    while (i < size) {
      uint64_t val = 0;
      if (!driver_read64(addr + i, val)) {
        std::printf("[MEM] READ driver FAILED at addr=0x%llx\n",
                    (unsigned long long)(addr + i));
        return false;
      }
      size_t copy = std::min(size - i, sizeof(uint64_t));
      std::memcpy(&out[i], &val, copy);
      i += copy;
    }
    return true;
  }
  // Fallback: local mock DRAM
  std::printf("[MEM] READ via mock-dram addr=0x%llx size=%zu\n",
              (unsigned long long)addr, size);
  if (addr + size > g.dram.size()) return false;
  out.assign(g.dram.begin()+addr, g.dram.begin()+addr+size);
  return true;
}

bool write_mem(uint64_t addr, const std::vector<uint8_t>& data){
  // Prefer host-attached process memory when address falls within mapped executable range
  if (g.host_attached && g.host_so_base && g.host_so_end &&
      addr >= g.host_so_base && (addr + data.size()) <= g.host_so_end) {
    std::printf("[MEM] WRITE via host-ptrace pid=%d addr=0x%llx size=%zu\n",
                g.host_pid, (unsigned long long)addr, (size_t)data.size());
    size_t i = 0;
    while (i < data.size()) {
      uint64_t chunk = 0;
      size_t copy = std::min(sizeof(uint64_t), data.size() - i);
      std::memcpy(&chunk, &data[i], copy);
      errno = 0;
      if (ptrace(PTRACE_POKEDATA, g.host_pid, (void*)(addr + i), (void*)chunk) != 0) {
        std::perror("ptrace(POKEDATA)");
        return false;
      }
      i += copy;
    }
    return true;
  }
  // Otherwise, use driver-host APIs to write device memory if available
  if (s_ccg) {
    std::printf("[MEM] WRITE via driver (%s) addr=0x%llx size=%zu\n",
                is_sram_addr(addr) ? "SRAM" : "DRAM",
                (unsigned long long)addr, (size_t)data.size());
    size_t i = 0;
    while (i < data.size()) {
      uint64_t val = 0;
      size_t copy = std::min(sizeof(uint64_t), data.size() - i);
      std::memcpy(&val, &data[i], copy);
      if (!driver_write64(addr + i, val)) {
        std::printf("[MEM] WRITE driver FAILED at addr=0x%llx\n",
                    (unsigned long long)(addr + i));
        return false;
      }
      i += copy;
    }
    return true;
  }
  // Fallback: local mock DRAM
  std::printf("[MEM] WRITE via mock-dram addr=0x%llx size=%zu\n",
              (unsigned long long)addr, (size_t)data.size());
  if (addr + data.size() > g.dram.size()) return false;
  std::copy(data.begin(), data.end(), g.dram.begin()+addr);
  return true;
}



void get_mailbox(uint32_t& cmd, uint32_t& status, uint64_t& buf_addr, uint32_t& count){
  cmd = g.mbox.cmd; status = g.mbox.status; buf_addr = g.mbox.buf_addr; count = g.mbox.count;
}

CoreInfo get_core_info(){
  CoreInfo info;
  info.itcm_size   = g.itcm.size();
  info.dtcm_size   = g.dtcm.size();
  info.dram_size   = g.dram.size();
  info.scalar_regs = static_cast<unsigned>(g.scalar.size());
  info.vector_regs = 64;
  info.const_regs  = 64;
  info.version     = SUBASE_VERSION_STRING;
  return info;
}

} // namespace zdb

// =========================
// Host attach (Linux only)
// =========================
namespace zdb {
#if DEVPORT(LINUX)
// Linux-only implementation
static bool get_child_pc(int pid, uint64_t& out_pc) {
  // x86_64-only
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0) return false;
  out_pc = regs.rip;
  return true;
}

bool host_attach_exe(const std::string& exe_path, const std::vector<std::string>& args) {
  if (g.host_attached) {
    std::puts("[HOST] already attached; detach first");
    return false;
  }
  // Resolve to an absolute/existing path before forking to avoid execvp failures.
  std::string exe = resolve_with_exe_dir(exe_path);
  {
    std::error_code ec;
    if (!std::filesystem::exists(exe, ec)) {
      std::printf("[HOST] executable not found: %s (resolved: %s)\n", exe_path.c_str(), exe.c_str());
      return false;
    }
  }
  pid_t child = fork();
  if (child < 0) { std::perror("fork"); return false; }
  if (child == 0) {
    // Child: request tracing then exec
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
      std::perror("ptrace(TRACEME)");
      _exit(1);
    }
    // Ensure cwd is the executable's directory so relative paths work
    {
      std::filesystem::path ep(exe);
      std::error_code ec;
      auto dir = ep.parent_path();
      if (!dir.empty()) {
        std::filesystem::current_path(dir, ec);
      }
    }
    // Do NOT inject extra stops; honor user's request to run without extra SIGSTOP
    // Build argv
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(exe.c_str()));
    for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    execvp(exe.c_str(), argv.data());
    std::perror("execvp");
    _exit(127);
  }
  // Parent: wait for child to stop
  int status = 0;
  if (waitpid(child, &status, 0) < 0) { std::perror("waitpid"); return false; }
  if (!WIFSTOPPED(status)) {
    std::puts("[HOST] child did not stop");
    return false;
  }
  g.host_pid = (int)child;
  g.host_attached = true;
  g.running = false; g.halted = true; g.reason = "host-attached";
  uint64_t pc = 0;
  if (get_child_pc(g.host_pid, pc)) {
    g.pc = pc;
  }
  std::printf("[HOST] attach-exe OK pid=%d pc=0x%llx\n", g.host_pid, (unsigned long long)g.pc);
  // Discover runtime base of the attached executable for source/variable relocation
  uint64_t b=0,e=0;
  if (find_image_base_in_maps(g.host_pid, exe, b, e)) {
    g.host_so_base = b; g.host_so_end = e;
    std::printf("[HOST] image map: base=0x%llx end=0x%llx (%s)\n",
                (unsigned long long)b, (unsigned long long)e, exe.c_str());
  }
  return true;
}

bool host_attach_pid(int pid) {
  if (g.host_attached) { std::puts("[HOST] already attached; detach first"); return false; }
  if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) { std::perror("ptrace(ATTACH)"); return false; }
  int status = 0;
  if (waitpid(pid, &status, 0) < 0) { std::perror("waitpid"); return false; }
  if (!WIFSTOPPED(status)) { std::puts("[HOST] target did not stop"); return false; }
  g.host_pid = pid; g.host_attached = true; g.running=false; g.halted=true; g.reason="host-attached";
  uint64_t pc = 0; if (get_child_pc(g.host_pid, pc)) g.pc = pc;
  std::printf("[HOST] attach-pid OK pid=%d pc=0x%llx\n", g.host_pid, (unsigned long long)g.pc);
  // Discover runtime base of the target executable
  uint64_t b=0,e=0;
  std::string exe_real = get_pid_exe_path(pid);
  if (!exe_real.empty() && find_image_base_in_maps(g.host_pid, exe_real, b, e)) {
    g.host_so_base = b; g.host_so_end = e;
    std::printf("[HOST] image map: base=0x%llx end=0x%llx (%s)\n",
                (unsigned long long)b, (unsigned long long)e, exe_real.c_str());
  }
  return true;
}

bool host_detach() {
  if (!g.host_attached) { std::puts("[HOST] no attached process"); return false; }
  if (ptrace(PTRACE_DETACH, g.host_pid, 0, 0) != 0) { std::perror("ptrace(DETACH)"); return false; }
  std::printf("[HOST] detached pid=%d\n", g.host_pid);
  g.host_attached = false; g.host_pid = -1;
  return true;
}

bool host_stepi(unsigned n) {
  if (!g.host_attached) { return false; }
  while (n--) {
    if (ptrace(PTRACE_SINGLESTEP, g.host_pid, 0, 0) != 0) {
    
      if (errno == ESRCH) {
        g.host_attached = false; g.host_pid = -1;
        g.halted = true; g.running = false; g.reason = "program-end";
        return false;
      }
  
      return false;
    }
    int status = 0; if (waitpid(g.host_pid, &status, 0) < 0) { return false; }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      g.host_attached = false; g.host_pid = -1;
      return false;
    }
    if (!WIFSTOPPED(status)) { return false; }
    uint64_t pc = 0; if (get_child_pc(g.host_pid, pc)) g.pc = pc;
    // Breakpoint check: runtime PC and relocated ELF address
    auto itbp = g.bp_id_by_addr.find(g.pc);
    if (itbp != g.bp_id_by_addr.end()) { g.halted=true; g.running=false; g.reason="breakpoint"; break; }
    if (!elfx::is_riscv_elf() && g.host_attached && g.host_so_base && g.pc >= g.host_so_base && g.pc < g.host_so_end) {
      uint64_t elf_vaddr_base = elfx::next_addr(0);
      uint64_t src_pc = g.pc - g.host_so_base + elf_vaddr_base;
      auto itbp2 = g.bp_id_by_addr.find(src_pc);
      if (itbp2 != g.bp_id_by_addr.end()) { g.halted=true; g.running=false; g.reason="breakpoint"; break; }
    }
  }
  return true;
}

bool host_cont() {
  if (!g.host_attached) { std::puts("[HOST] not attached"); return false; }
  if (ptrace(PTRACE_CONT, g.host_pid, 0, 0) != 0) { std::perror("ptrace(CONT)"); return false; }
  int status=0; if (waitpid(g.host_pid, &status, 0) < 0) { std::perror("waitpid"); return false; }
  uint64_t pc=0; if (get_child_pc(g.host_pid, pc)) g.pc = pc;
  std::printf("[HOST] stopped → PC=0x%llx\n", (unsigned long long)g.pc);
  return true;
}
#endif // DEVPORT(LINUX)

} // namespace zdb

