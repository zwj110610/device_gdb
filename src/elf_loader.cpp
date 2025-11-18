#include "elf_loader.h"
#include <array>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <regex>
#include <sstream>
#include <unordered_map>
#include <cerrno>     // for errno/strerror
#include <filesystem> // for std::filesystem path resolution

namespace {


// Resolve external tool path with the following priority:
// 1) Environment variable (e.g. ZDB_NM)
// 2) Current working directory for common tool names
// 3) Tests directory: source/tests/zdb.linux for common tool names
// 4) Fallback to first candidate name (use PATH)
static std::string resolve_tool(const char* env, std::initializer_list<const char*> candidates) {
    if (const char* p = std::getenv(env)) {
        if (p && *p) return std::string(p);
    }

    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path cwd = fs::current_path(ec);
    if (!ec) {
        for (const char* name : candidates) {
            fs::path p = cwd / name;
            if (fs::exists(p)) return fs::absolute(p).string();
        }
    }

    // Scan upwards to locate source/tests/zdb.linux
    fs::path up = cwd;
    for (int i = 0; i < 6; ++i) {
        if (up.empty()) break;
        fs::path testdir = up / "source" / "tests" / "zdb.linux";
        for (const char* name : candidates) {
            fs::path p = testdir / name;
            if (fs::exists(p)) return fs::absolute(p).string();
        }
        up = up.parent_path();
    }

    return std::string(*candidates.begin());
}

// Extract quoted name from a DWARF line like:
//   DW_AT_name            ("sim_entry")
//   DW_AT_linkage_name    ("_Z10sim_entryi")
// Returns empty string if not matched.
static std::string dwarfo_extract_name(const std::string& line) {
    // Accept common objdump formats:
    //   DW_AT_name            ("sim_entry")
    //   DW_AT_name            "sim_entry"
    //   DW_AT_name            sim_entry
    //   DW_AT_name            : (indirect string, offset: 0x146): sim_entry
    // and linkage_name variants (quoted or unquoted, with optional parentheses)
    std::smatch m;
    // Prefer quoted capture first
    {
        std::regex r_quoted(R"(DW_AT_(?:name|linkage_name)\s*(?:\(\s*)?\"([^\"]+)\"(?:\s*\))?)");
        if (std::regex_search(line, m, r_quoted)) return m[1].str();
    }
    // If the line contains a colon-separated form, take the last colon segment as the name
    if (line.find("DW_AT_name") != std::string::npos || line.find("DW_AT_linkage_name") != std::string::npos) {
        auto pos = line.find_last_of(':');
        if (pos != std::string::npos && pos + 1 < line.size()) {
            std::string tail = line.substr(pos + 1);
            // trim spaces
            auto l = tail.find_first_not_of(" \t");
            auto r = tail.find_last_not_of(" \t\r\n)");
            if (l != std::string::npos) {
                std::string name = (r == std::string::npos) ? tail.substr(l) : tail.substr(l, r - l + 1);
                if (!name.empty()) return name;
            }
        }
    }
    // Fallback: unquoted token up to whitespace or closing paren
    {
        std::regex r_unquoted(R"(DW_AT_(?:name|linkage_name)\s*(?:\(\s*)?([^\s\)\(]+)(?:\s*\))?)");
        if (std::regex_search(line, m, r_unquoted)) return m[1].str();
    }
    return {};
}

// True when the DWARF line is a name/linkage_name exactly equal to needle.
static bool dwarfo_name_equals(const std::string& line, const std::string& needle) {
    const std::string n = dwarfo_extract_name(line);
    return !n.empty() && n == needle;
}

const std::string kNM        = resolve_tool("ZDB_NM",        {"nm","riscv64-unknown-elf-nm"});
const std::string kOBJDUMP   = resolve_tool("ZDB_OBJDUMP",   {"objdump","riscv64-unknown-elf-objdump"});
const std::string kOBJCOPY   = resolve_tool("ZDB_OBJCOPY",   {"objcopy","riscv64-unknown-elf-objcopy"});
const std::string kADDR2LINE = resolve_tool("ZDB_ADDR2LINE", {"addr2line","riscv64-unknown-elf-addr2line", "addr2line"});

std::string shell_quote(const std::string& s){
    std::string out="'";
    for(char c: s) out += (c=='\'' ? "'\\''" : std::string(1,c));
    out+="'";
    return out;
}


std::string run_cmd(const std::vector<std::string>& args){
    std::string cmd;
    for(size_t i=0;i<args.size();++i){
        if(i) cmd.push_back(' ');
        bool need_q = args[i].find_first_of(" \t\"'(){}$&|;<>`\\") != std::string::npos;
        cmd += need_q ? shell_quote(args[i]) : args[i];
    }

    std::array<char,4096> buf{};
    std::string out;

    FILE* pipe = popen(cmd.c_str(),"r");
    if(!pipe){
        std::fprintf(stderr, "popen failed: %s (cmd=%s)\n",
                     std::strerror(errno), cmd.c_str());
        return std::string(); 
    }

    while(true){
        size_t n=fread(buf.data(),1,buf.size(),pipe);
        if(n==0) break;
        out.append(buf.data(),n);
    }
    pclose(pipe);
    return out;
}

// Try a preferred tool first, then fall back to a generic host tool.
static bool contains_tool_error(const std::string& s){
    return s.find("Unable to recognise the format") != std::string::npos ||
           s.find("can't disassemble") != std::string::npos ||
           s.find("architecture UNKNOWN") != std::string::npos;
}

static std::string run_with_fallback(const std::string& primary,
                                     const std::string& fallback,
                                     const std::vector<std::string>& args){
    std::vector<std::string> cmd;
    cmd.reserve(args.size()+1);
    cmd.push_back(primary);
    cmd.insert(cmd.end(), args.begin(), args.end());
    std::string out = run_cmd(cmd);
    if (out.empty() || contains_tool_error(out)){
        cmd[0] = fallback;
        out = run_cmd(cmd);
    }
    return out;
}

static std::string run_objdump(const std::vector<std::string>& args){
    return run_with_fallback(kOBJDUMP, "objdump", args);
}
static std::string run_addr2line(const std::vector<std::string>& args){
    return run_with_fallback(kADDR2LINE, "addr2line", args);
}
static std::string run_nm(const std::vector<std::string>& args){
    return run_with_fallback(kNM, "nm", args);
}
static std::string run_objcopy(const std::vector<std::string>& args){
    return run_with_fallback(kOBJCOPY, "objcopy", args);
}


bool prefix_in_list(const std::string& name, const std::vector<std::string>& lst){
    for (const auto& pre : lst) {
        if (pre.empty()) continue;
        if (name.rfind(pre,0)==0) return true; 
    }
    return false;
}
std::string dirname_of(const std::string& p){
    auto pos = p.find_last_of("/\\");
    return (pos==std::string::npos) ? std::string(".") : p.substr(0,pos);
}
std::string basename_noext(const std::string& p){
    auto pos = p.find_last_of("/\\");
    std::string bn = (pos==std::string::npos) ? p : p.substr(pos+1);
    auto dot = bn.find_last_of('.');
    if (dot!=std::string::npos) bn.resize(dot);
    return bn;
}
void ensure_parent_exists(const std::string& /*path*/) {
    
}


struct SecHdr { std::string name; uint64_t vma=0; uint64_t size=0; };


std::vector<SecHdr> parse_objdump_headers(const std::string& hdr){
   
    std::regex rl(R"(^\s*\d+\s+(\S+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+).*$)");
    std::vector<SecHdr> out;
    std::istringstream iss(hdr);
    std::string line;
    while(std::getline(iss,line)){
        std::smatch m;
        if(!std::regex_match(line,m,rl)) continue;
        SecHdr s;
        s.name = m[1].str();
        s.size = std::stoull(m[2].str(),nullptr,16);
        s.vma  = std::stoull(m[3].str(),nullptr,16); // VMA
        if(s.size>0) out.push_back(s);
    }
    return out;
}


bool dump_section_to_file(const std::string& elf, const std::string& sec, const std::string& outbin){
    (void)run_objcopy({"--dump-section", sec+"="+outbin, elf});
    std::ifstream ifs(outbin, std::ios::binary);
    return (bool)ifs; 
}


bool merge_sections_to_bin(const std::string& elf,
                           const std::vector<SecHdr>& secs,
                           const std::string& out_path,
                           uint64_t& out_base,
                           uint64_t& out_size)
{
    if (secs.empty()) { 
        {
            std::ofstream ofs(out_path, std::ios::binary);
        }
        out_base = 0; out_size = 0; return true;
    }
    uint64_t base = secs[0].vma, end = secs[0].vma + secs[0].size;
    for (auto& s : secs) {
        base = std::min(base, s.vma);
        end  = std::max(end,  s.vma + s.size);
    }
    if (end <= base) { 
        {
            std::ofstream ofs(out_path, std::ios::binary);
        }
        out_base = 0; out_size = 0; return true;
    }
    std::vector<uint8_t> buf((size_t)(end - base), 0);

   
    for (auto& s : secs) {
        std::string tmp = "/tmp/zdb_sec_" + s.name + ".bin";
        if (!dump_section_to_file(elf, s.name, tmp)) continue;

        std::ifstream ifs(tmp, std::ios::binary);
        if (!ifs) continue;
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(ifs)), {});
        if (data.size() != s.size) {
        
            data.resize((size_t)s.size, 0);
        }
        uint64_t off = s.vma - base;
        if (off + data.size() <= buf.size())
            std::copy(data.begin(), data.end(), buf.begin() + (size_t)off);
    }

    ensure_parent_exists(out_path);
    std::ofstream of(out_path, std::ios::binary);
    if (!of) return false;
    of.write(reinterpret_cast<const char*>(buf.data()), (std::streamsize)buf.size());
    of.close();

    out_base = base;
    out_size = (uint64_t)buf.size();
    return true;
}


std::string g_elf;
std::map<std::string,uint64_t> g_symtab;
std::unordered_map<uint64_t, zdb::elfx::SourceLoc> g_addr2src;
// Map from "<file>:<line>" to all addresses that map to that source line
std::unordered_map<std::string, std::vector<uint64_t>> g_srcline2addrs;
// Sorted list of all instruction addresses from disassembly
static std::vector<uint64_t> g_disasm_addrs;
// Cached architecture hint parsed from objdump -f
static bool g_is_riscv = true;

inline std::string make_srckey(const std::string& file, int line){
    return file + ":" + std::to_string(line);
}


void parse_nm_defined(const std::string& nm_out){
    std::regex r(R"(^\s*([0-9A-Fa-f]+)\s+\w\s+(\S+)\s*$)");
    g_symtab.clear();
    std::istringstream iss(nm_out);
    std::string line;
    while(std::getline(iss,line)){
        std::smatch m;
        if(!std::regex_match(line,m,r)) continue;
        uint64_t addr = std::stoull(m[1].str(),nullptr,16);
        std::string name = m[2].str();
        g_symtab[name]=addr;
    }
}


zdb::elfx::SourceLoc query_addr2line(uint64_t addr){
    auto it = g_addr2src.find(addr);
    if (it!=g_addr2src.end()) return it->second;

    char abuf[32];
    std::snprintf(abuf,sizeof(abuf),"0x%llx",(unsigned long long)addr);
    std::string out = run_addr2line({"-e", g_elf, "-f", "-C", abuf});
    std::istringstream iss(out);
    std::string func, fileline;
    std::getline(iss, func);
    std::getline(iss, fileline);

    zdb::elfx::SourceLoc sl; sl.func=func;
    auto pos = fileline.rfind(':');
    if (pos!=std::string::npos) {
        sl.file = fileline.substr(0,pos);
        sl.line = std::atoi(fileline.substr(pos+1).c_str());
    } else {
        sl.file = fileline;
        sl.line = 0;
    }
    g_addr2src[addr]=sl;
    return sl;
}

// Extract instruction addresses from objdump disassembly text.
// We look for lines starting with an address like: "  401136:"
static std::vector<uint64_t> parse_objdump_disasm_addrs(const std::string& dis){
    std::vector<uint64_t> addrs;
    std::regex r(R"(^\s*([0-9A-Fa-f]+):\s.*$)");
    std::istringstream iss(dis);
    std::string line;
    while (std::getline(iss, line)){
        std::smatch m;
        if (!std::regex_match(line, m, r)) continue;
        const std::string& hex = m[1].str();
        errno = 0;
        char* endp = nullptr;
        unsigned long long v = std::strtoull(hex.c_str(), &endp, 16);
        if (errno == ERANGE || endp == hex.c_str()) continue; // parse failure
        uint64_t a = static_cast<uint64_t>(v);
        addrs.push_back(a);
    }
    // Dedup consecutive duplicates
    addrs.erase(std::unique(addrs.begin(), addrs.end()), addrs.end());
    return addrs;
}

// Build full line table by disassembling to get all instruction addresses,
// then batch-resolving them via addr2line. Populates g_addr2src and g_srcline2addrs.
static void build_full_line_table(){
    g_srcline2addrs.clear();
    g_disasm_addrs.clear();

    if (g_elf.empty()) return;
    auto dis = run_objdump({"-d", g_elf});
    if (dis.empty()) return;
    auto addrs = parse_objdump_disasm_addrs(dis);
    if (addrs.empty()) return;
    g_disasm_addrs = addrs;
    std::sort(g_disasm_addrs.begin(), g_disasm_addrs.end());
    g_disasm_addrs.erase(std::unique(g_disasm_addrs.begin(), g_disasm_addrs.end()), g_disasm_addrs.end());

    const size_t batch = 256; // batch size for addr2line
    std::vector<std::string> args;
    args.reserve(batch + 5);

    for (size_t i = 0; i < addrs.size(); i += batch){
        size_t n = std::min(batch, addrs.size() - i);
        args.clear();
        args.push_back("-e"); args.push_back(g_elf);
        args.push_back("-f"); args.push_back("-C");

        // Append addresses
        for (size_t j = 0; j < n; ++j){
            char abuf[32];
            std::snprintf(abuf, sizeof(abuf), "0x%llx", (unsigned long long)addrs[i+j]);
            args.emplace_back(abuf);
        }

        std::string out = run_addr2line(args);
        if (out.empty()) continue;

        std::istringstream iss(out);
        for (size_t j = 0; j < n; ++j){
            std::string func, fileline;
            if (!std::getline(iss, func)) break;
            if (!std::getline(iss, fileline)) break;

            zdb::elfx::SourceLoc sl; sl.func = func;
            auto pos = fileline.rfind(':');
            if (pos != std::string::npos){
                sl.file = fileline.substr(0, pos);
                sl.line = std::atoi(fileline.substr(pos+1).c_str());
            } else {
                sl.file = fileline;
                sl.line = 0;
            }

            uint64_t addr = addrs[i+j];
            g_addr2src[addr] = sl;
            if (!sl.file.empty() && sl.file != "??" && sl.line > 0){
                auto key = make_srckey(sl.file, sl.line);
                auto& vec = g_srcline2addrs[key];
                vec.push_back(addr);
            }
        }
    }

    // Dedup and sort address vectors per source line
    for (auto& kv : g_srcline2addrs){
        auto& v = kv.second;
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
    }
}

} // anonymous


namespace zdb::elfx {

bool build_bins_and_indices(const std::string& elf_path,
                            const std::vector<std::string>& itcm_sections,
                            const std::vector<std::string>& dtcm_sections,
                            BinImage& out_inst,
                            BinImage& out_data,
                            const std::string& out_dir,
                            bool /*riscv_mode*/)
{
    g_elf = elf_path;
    g_addr2src.clear();
    g_is_riscv = true; // default until proven otherwise


    const std::string dir = out_dir.empty() ? ::dirname_of(elf_path) : out_dir;
    const std::string stem = ::basename_noext(elf_path);
    out_inst.path = dir + "/" + stem + ".inst.bin";
    out_data.path = dir + "/" + stem + ".data.bin";


    auto hdr = run_objdump({"-h", elf_path});
    if (hdr.empty()) return false;  
    auto all = ::parse_objdump_headers(hdr);

    std::vector<SecHdr> itcms, dtcms;
    for (auto& s : all) {
        if (s.size == 0) continue;
        if (prefix_in_list(s.name, itcm_sections)) itcms.push_back(s);
        if (prefix_in_list(s.name, dtcm_sections)) dtcms.push_back(s);
    }

  
    if (!merge_sections_to_bin(elf_path, itcms, out_inst.path, out_inst.base, out_inst.size))
        return false;
    if (!merge_sections_to_bin(elf_path, dtcms, out_data.path, out_data.base, out_data.size))
        return false;

    auto nm_out = run_nm({"-n", "--defined-only", elf_path});
    if (!nm_out.empty()) {
        ::parse_nm_defined(nm_out);
    } else {
        g_symtab.clear();
    }

    // Detect architecture via objdump -f
    {
        std::string finfo = run_objdump({"-f", elf_path});
        if (!finfo.empty()) {
            // Look for a line like: "architecture: riscv:rv64, ..." or "architecture: i386:x86-64, ..."
            std::regex ra(R"(architecture:\s*([^,]+))");
            std::smatch m;
            if (std::regex_search(finfo, m, ra)) {
                std::string arch = m[1].str();
                // normalize to lower
                std::transform(arch.begin(), arch.end(), arch.begin(), [](unsigned char c){ return (char)std::tolower(c); });
                g_is_riscv = (arch.find("riscv") != std::string::npos);
            }
        }
    }

    // Build decoded line table for address<->source queries.
    build_full_line_table();

    return true;
}

bool sym_lookup(const std::string& name, uint64_t& addr_out){
    auto it = g_symtab.find(name);
    if (it==g_symtab.end()) return false;
    addr_out = it->second; return true;
}

std::vector<std::pair<std::string,uint64_t>> all_symbols(){
    std::vector<std::pair<std::string,uint64_t>> v;
    v.reserve(g_symtab.size());
    for (auto& kv : g_symtab) v.emplace_back(kv.first, kv.second);
    std::sort(v.begin(), v.end(), [](auto&a,auto&b){ return a.second < b.second; });
    return v;
}

SourceLoc addr_to_source(uint64_t addr){
    if (g_elf.empty()) return {};
    auto it = g_addr2src.find(addr);
    if (it != g_addr2src.end()) return it->second;
    return ::query_addr2line(addr);
}

std::vector<uint64_t> line_to_addresses(const std::string& file, int line){
    std::vector<uint64_t> out;
    if (g_elf.empty()) return out;
    auto it = g_srcline2addrs.find(make_srckey(file, line));
    if (it == g_srcline2addrs.end()) return out;
    return it->second; // already deduped & sorted
}

std::vector<uint64_t> line_to_addresses(int line){
    std::vector<uint64_t> out;
    if (g_elf.empty()) return out;
    for (const auto& kv : g_srcline2addrs){
        const std::string& key = kv.first;
        auto pos = key.rfind(':');
        if (pos == std::string::npos) continue;
        const std::string ln_str = key.substr(pos+1);
        errno = 0;
        char* endp = nullptr;
        long v = std::strtol(ln_str.c_str(), &endp, 10);
        if (errno == ERANGE || endp == ln_str.c_str()) continue; // parse failure
        int ln = static_cast<int>(v);
        if (ln == line){
            const auto& vec = kv.second;
            out.insert(out.end(), vec.begin(), vec.end());
        }
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

const std::string& current_elf(){ return g_elf; }

// Return next instruction address strictly greater than pc from disassembly list.
// If not available, return the same pc.
uint64_t next_addr(uint64_t pc){
    if (g_disasm_addrs.empty()) return pc;
    auto it = std::upper_bound(g_disasm_addrs.begin(), g_disasm_addrs.end(), pc);
    if (it == g_disasm_addrs.end()) return pc;
    return *it;
}

bool is_riscv_elf(){ return g_is_riscv; }

// Determine if a function's frame base uses CFA: DW_AT_frame_base (DW_OP_call_frame_cfa)
static bool lookup_func_uses_cfa_framebase(const std::string& func_name)
{
    if (g_elf.empty()) return false;
    std::string dwarfo = run_objdump({"--dwarf=info", "-C", g_elf});
    if (dwarfo.empty()) return false;
    std::istringstream iss(dwarfo);
    std::string line;
    bool in_func = false;
    while (std::getline(iss, line)) {
        if (line.find("DW_TAG_subprogram") != std::string::npos) {
            in_func = false; // reset until we confirm name
            continue;
        }
        if (dwarfo_name_equals(line, func_name)) {
            in_func = true; // we are in the target function block
            continue;
        }
        if (!in_func) continue;
        if (line.find("DW_AT_frame_base") != std::string::npos) {
            // Example: DW_AT_frame_base    (DW_OP_call_frame_cfa)
            if (line.find("DW_OP_call_frame_cfa") != std::string::npos) return true;
            // Some toolchains may print the operator on the following line; peek ahead up to a few lines
            std::streampos pos = iss.tellg();
            for (int i = 0; i < 4; ++i) {
                std::string next;
                if (!std::getline(iss, next)) break;
                if (next.find("DW_OP_call_frame_cfa") != std::string::npos) { return true; }
                // Stop if a new attribute or tag begins
                if (next.find("DW_TAG_") != std::string::npos || (next.find("DW_AT_") != std::string::npos && next.find("DW_AT_frame_base") == std::string::npos)) break;
            }
            // restore stream to after current line if not found
            iss.clear();
            iss.seekg(pos);
        }
        // Heuristic: end when we encounter the next subprogram
    }
    return false;
}

// Try to parse DWARF info using objdump to find a local variable with a DW_OP_fbreg location.
// This is a best-effort, limited parser suitable for simple cases.
bool lookup_local_fbreg(const std::string& func_name,
                        const std::string& var_name,
                        long& fbreg_offset)
{
    fbreg_offset = 0;
    if (g_elf.empty()) return false;
    // Get DWARF info. We keep it simple: scan for the subprogram with matching name,
    // then within its block, find a DW_TAG_variable whose DW_AT_name matches var_name,
    // and a DW_AT_location containing "DW_OP_fbreg" with an integer offset.
    std::string dwarfo = run_objdump({"--dwarf=info", "-C", g_elf});
    if (dwarfo.empty()) return false;

    std::istringstream iss(dwarfo);
    std::string line;
    bool in_func = false;
    long found_offset = 0;
    bool found_var = false;
    bool in_var_scope = false;
    bool in_location = false; // after seeing DW_AT_location, subsequent lines may contain DW_OP_*
    while (std::getline(iss, line)) {
        // Normalize spaces for simple matching
        if (line.find("DW_TAG_subprogram") != std::string::npos) {
            in_func = false; // reset until we confirm name
            found_var = false;
            in_location = false;
            continue;
        }
        if (dwarfo_name_equals(line, func_name)) {
            // Enter function scope
            in_func = true;
            found_var = false;
            in_var_scope = false;
            in_location = false;
            continue;
        }
        if (!in_func) continue;
        // Inside the function block
        if (line.find("DW_TAG_variable") != std::string::npos || line.find("DW_TAG_formal_parameter") != std::string::npos) {
            // New variable scope; reset flags
            found_var = false;
            in_var_scope = true;
            found_offset = 0;
            in_location = false;
            continue;
        }
        if (in_var_scope && dwarfo_name_equals(line, var_name)) {
            found_var = true;
            // keep scanning for location
            continue;
        }
        // Start of location attribute: subsequent lines may list DW_OP_* entries
        if (found_var && line.find("DW_AT_location") != std::string::npos) {
            in_location = true;
        }
        // Location may be printed on the same line or following lines (location list)
        if (found_var && in_location && line.find("DW_OP_fbreg") != std::string::npos) {
            // Extract the integer after fbreg (no exceptions):
            // e.g., "DW_AT_location        (DW_OP_fbreg: -16)"
            std::regex r(R"(DW_OP_fbreg:\s*([+-]?[0-9]+))");
            std::smatch m;
            if (std::regex_search(line, m, r)) {
                const std::string s = m[1].str();
                errno = 0;
                char* endp = nullptr;
                long v = std::strtol(s.c_str(), &endp, 10);
                if (errno == 0 && endp != s.c_str()) {
                    found_offset = v;
                    fbreg_offset = found_offset;
                    return true;
                }
            }
        }
        // Heuristic: end of location block when hitting another attribute or a new tag
        if (in_location && (line.find("DW_TAG_") != std::string::npos || (line.find("DW_AT_") != std::string::npos && line.find("DW_AT_location") == std::string::npos))) {
            in_location = false;
        }
        // Exit function scope heuristic: next subprogram or end of unit will reset
    }
    return false;
}

// Try to parse DWARF info to find register-based location expressions for a local variable
// Supports simple cases:
//  - DW_OP_regN / DW_OP_regx: <num>
//  - DW_OP_bregN: <offset> / DW_OP_bregx: <num> <offset>
bool lookup_local_regloc(const std::string& func_name,
                         const std::string& var_name,
                         int& regnum,
                         bool& is_breg,
                         long& breg_offset)
{
    regnum = -1; is_breg = false; breg_offset = 0;
    if (g_elf.empty()) return false;
    std::string dwarfo = run_objdump({"--dwarf=info", "-C", g_elf});
    if (dwarfo.empty()) return false;

    std::istringstream iss(dwarfo);
    std::string line;
    bool in_func = false;
    bool found_var = false;
    bool in_var_scope = false;
    bool in_location = false;
    while (std::getline(iss, line)) {
        if (line.find("DW_TAG_subprogram") != std::string::npos) {
            in_func = false;
            found_var = false;
            in_var_scope = false;
            in_location = false;
            continue;
        }
        if (dwarfo_name_equals(line, func_name)) {
            in_func = true;
            found_var = false;
            in_var_scope = false;
            in_location = false;
            continue;
        }
        if (!in_func) continue;
        if (line.find("DW_TAG_variable") != std::string::npos || line.find("DW_TAG_formal_parameter") != std::string::npos) {
            found_var = false;
            in_var_scope = true;
            breg_offset = 0;
            in_location = false;
            continue;
        }
        if (in_var_scope && dwarfo_name_equals(line, var_name)) {
            found_var = true;
            continue;
        }
        if (!found_var) continue;
        if (line.find("DW_AT_location") != std::string::npos) {
            in_location = true;
        }
        if (in_location) {
            // Patterns:
            //   DW_OP_reg5
            //   DW_OP_regx: 5
            //   DW_OP_breg6: -16
            //   DW_OP_bregx: 6, -16
            {
                std::regex r_regn(R"(DW_OP_reg(\d+))");
                std::smatch m;
                if (std::regex_search(line, m, r_regn)) {
                    regnum = std::stoi(m[1].str());
                    is_breg = false;
                    return true;
                }
            }
            {
                std::regex r_regx(R"(DW_OP_regx:\s*([0-9]+))");
                std::smatch m;
                if (std::regex_search(line, m, r_regx)) {
                    regnum = std::stoi(m[1].str());
                    is_breg = false;
                    return true;
                }
            }
            {
                std::regex r_bregn(R"(DW_OP_breg(\d+):\s*([+-]?[0-9]+))");
                std::smatch m;
                if (std::regex_search(line, m, r_bregn)) {
                    regnum = std::stoi(m[1].str());
                    errno = 0; char* endp = nullptr;
                    long v = std::strtol(m[2].str().c_str(), &endp, 10);
                    if (errno == 0 && endp != m[2].str().c_str()) {
                        breg_offset = v;
                        is_breg = true;
                        return true;
                    }
                }
            }
            {
                std::regex r_bregx(R"(DW_OP_bregx:\s*([0-9]+)\s*,\s*([+-]?[0-9]+))");
                std::smatch m;
                if (std::regex_search(line, m, r_bregx)) {
                    regnum = std::stoi(m[1].str());
                    errno = 0; char* endp = nullptr;
                    long v = std::strtol(m[2].str().c_str(), &endp, 10);
                    if (errno == 0 && endp != m[2].str().c_str()) {
                        breg_offset = v;
                        is_breg = true;
                        return true;
                    }
                }
            }
            // End of location list when another attribute appears or new tag starts
            if (line.find("DW_TAG_") != std::string::npos || (line.find("DW_AT_") != std::string::npos && line.find("DW_AT_location") == std::string::npos)) {
                in_location = false;
            }
        }
    }
    return false;
}

// Try to parse DWARF info to find an absolute address for a static local (DW_OP_addr)
bool lookup_local_addr(const std::string& func_name,
                       const std::string& var_name,
                       uint64_t& abs_addr)
{
    abs_addr = 0;
    if (g_elf.empty()) return false;
    std::string dwarfo = run_objdump({"--dwarf=info", "-C", g_elf});
    if (dwarfo.empty()) return false;

    std::istringstream iss(dwarfo);
    std::string line;
    bool in_func = false;
    bool found_var = false;
    bool in_var_scope = false;
    bool in_location = false;
    while (std::getline(iss, line)) {
        if (line.find("DW_TAG_subprogram") != std::string::npos) {
            in_func = false;
            found_var = false;
            in_var_scope = false;
            in_location = false;
            continue;
        }
        if (dwarfo_name_equals(line, func_name)) {
            in_func = true;
            found_var = false;
            in_var_scope = false;
            in_location = false;
            continue;
        }
        if (!in_func) continue;
        if (line.find("DW_TAG_variable") != std::string::npos || line.find("DW_TAG_formal_parameter") != std::string::npos) {
            found_var = false;
            in_var_scope = true;
            in_location = false;
            continue;
        }
        if (in_var_scope && dwarfo_name_equals(line, var_name)) {
            found_var = true;
            continue;
        }
        if (!found_var) continue;
        if (line.find("DW_AT_location") != std::string::npos) {
            in_location = true;
        }
        if (in_location && line.find("DW_OP_addr") != std::string::npos) {
            // Examples:
            //   DW_AT_location        (DW_OP_addr 0x0000000000404050)
            //   DW_AT_location        (DW_OP_addr: 0x404050)
            std::regex r(R"(DW_OP_addr[^0-9a-fA-F]*0x([0-9a-fA-F]+))");
            std::smatch m;
            if (std::regex_search(line, m, r)) {
                const std::string hex = m[1].str();
                errno = 0; char* endp = nullptr;
                unsigned long long v = std::strtoull(hex.c_str(), &endp, 16);
                if (errno == 0 && endp != hex.c_str()) { abs_addr = (uint64_t)v; return true; }
            }
        }
        if (in_location && (line.find("DW_TAG_") != std::string::npos || (line.find("DW_AT_") != std::string::npos && line.find("DW_AT_location") == std::string::npos))) {
            in_location = false;
        }
    }
    return false;
}

bool resolve_variable(const std::string& name, uint64_t pc, VarInfo& out){
    out = VarInfo{};
    out.name = name;
    out.size = 8; // default
    if (g_elf.empty()) return false;

    // Prefer global symbol table
    uint64_t addr = 0;
    if (sym_lookup(name, addr)) {
        out.addr = addr;
        out.is_global = true;
        // annotate source if possible
        auto sl = addr_to_source(addr);
        out.func = sl.func; out.file = sl.file; out.line = sl.line;
        return true;
    }

    // Try local: need current function from pc
    auto cur = addr_to_source(pc);
    out.func = cur.func; out.file = cur.file; out.line = cur.line;

    // Static local: absolute address via DW_OP_addr
    uint64_t abs = 0;
    if (!cur.func.empty() && lookup_local_addr(cur.func, name, abs)) {
        out.addr = abs;
        out.is_global = true; // memory-backed at absolute address
        out.in_register = false;
        return true;
    }

    long fbreg = 0;
    if (!cur.func.empty() && lookup_local_fbreg(cur.func, name, fbreg)) {
        // Caller must compute final address with frame base (fp)
        // We cannot know fp here; leave addr as fbreg sentinel encoded as signed offset.
        // Upstream will add fp to this offset.
        out.addr = static_cast<uint64_t>(static_cast<int64_t>(fbreg));
        out.is_global = false;
        out.in_register = false;
        // Determine if this function uses CFA for frame base; inform upstream
        out.uses_cfa_base = lookup_func_uses_cfa_framebase(cur.func);
        return true;
    }
    // Try register locations
    int regn = -1; bool is_breg = false; long bofs = 0;
    if (!cur.func.empty() && lookup_local_regloc(cur.func, name, regn, is_breg, bofs)) {
        out.is_global = false;
        out.in_register = true;
        out.regnum = regn;
        out.is_breg = is_breg;
        out.breg_offset = bofs;
        return true;
    }
    return false;
}

} // namespace zdb::elfx


