#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <utility>

namespace zdb::elfx {


struct SourceLoc {
    std::string func;
    std::string file;
    int         line = 0;
};


struct BinImage {
    std::string path;   
    uint64_t    base = 0; 
    uint64_t    size = 0; 
};


bool build_bins_and_indices(const std::string& elf_path,
                            const std::vector<std::string>& itcm_sections,
                            const std::vector<std::string>& dtcm_sections,
                            BinImage& out_inst,
                            BinImage& out_data,
                            const std::string& out_dir = std::string(),
                            bool riscv_mode = true);


bool sym_lookup(const std::string& name, uint64_t& addr_out);
std::vector<std::pair<std::string,uint64_t>> all_symbols();


SourceLoc addr_to_source(uint64_t addr);

// Query all addresses that map to the given source file and line.
// Returns a sorted, deduplicated list. Empty if no mapping or not built.
std::vector<uint64_t> line_to_addresses(const std::string& file, int line);

// Convenience overload: query by line number across all files.
// Aggregates addresses from any file that has this line number.
std::vector<uint64_t> line_to_addresses(int line);


// Return the path of the most recently processed ELF (from the last build)
const std::string& current_elf();

// Disassembly-driven stepping helpers
// Return next instruction address strictly greater than pc; if unavailable, returns pc.
uint64_t next_addr(uint64_t pc);
// Architecture hint parsed from objdump; true if ELF is RISC-V.
bool is_riscv_elf();

// ===== Variables (globals + simple locals) =====
struct VarInfo {
    std::string name;
    std::string func;
    std::string file;
    int         line = 0;
    uint64_t    addr = 0;
    size_t      size = 0;    // default 8 if unknown
    bool        is_global = false;
    // Extended local location info
    // If a local lives in a register, set in_register=true and regnum to DWARF reg number.
    bool        in_register = false;
    int         regnum = -1;        // DWARF register number (for x86_64: 0=rax, 5=rdi, 6=rbp, 7=rsp, 16=rip, etc.)
    // If a local is described by DW_OP_breg{N}: offset, set is_breg=true
    bool        is_breg = false;
    long        breg_offset = 0;    // offset to add to the base register value
    // If a local uses DW_OP_fbreg offset relative to CFA, mark true.
    // Upstream may approximate CFA as rbp+16 on x86_64 with frame pointer enabled.
    bool        uses_cfa_base = false;
};

// Resolve variable by name at a given PC.
// - Tries global symbols via nm first.
// - Falls back to DWARF local:
//   * DW_OP_fbreg: uses frame-base offset
//   * DW_OP_reg* : variable value is held in a register
//   * DW_OP_breg*: address is base-register plus offset
bool resolve_variable(const std::string& name, uint64_t pc, VarInfo& out);

// Internal helper: find DW_OP_fbreg offset for a local in a function.
// Returns true if found and sets fbreg_offset (may be negative).
bool lookup_local_fbreg(const std::string& func_name,
                        const std::string& var_name,
                        long& fbreg_offset);

// Internal helper: find DW_OP_regx / DW_OP_regN / DW_OP_bregx / DW_OP_bregN for a local.
// Returns true and sets regnum; if breg, also sets offset and is_breg=true.
bool lookup_local_regloc(const std::string& func_name,
                         const std::string& var_name,
                         int& regnum,
                         bool& is_breg,
                         long& breg_offset);

// Internal helper: find DW_OP_addr absolute address for a static local inside a function.
// Returns true and sets abs_addr if found.
bool lookup_local_addr(const std::string& func_name,
                       const std::string& var_name,
                       uint64_t& abs_addr);

} // namespace zdb::elfx


