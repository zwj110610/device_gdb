#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include "zdb_backend.h"     
#include "zdb_cmd.h"


namespace cmd {



static inline void ensure_size(std::vector<uint8_t>& buf, size_t need) {
    if (buf.size() < need) buf.resize(need, 0);
}


bool hex_load_elf(const std::string& elf_path,
                  uint64_t itcm_addr,
                  uint64_t dtcm_addr,
                  bool wakeup) {
    return zdb::hex_load_elf(elf_path, itcm_addr, dtcm_addr, wakeup);
}

bool hex_load(const std::string& itcm,
                  const std::string& dtcm,
                  uint64_t itcm_addr,
                  uint64_t dtcm_addr,
                  bool wakeup,
                  uint64_t boot_addr) {
    return zdb::hex_load(itcm, dtcm, itcm_addr, dtcm_addr, wakeup, boot_addr);
}

void reload() {
    if (!zdb::reload())
        std::puts("RELOAD FAIL");
    else
        std::puts("RELOAD OK");
}

void load_assist(const std::string& path) {
    if (path.empty()) {
        std::puts("usage: load-assist <file>");
        return;
    }
    std::printf("load-assist '%s'\n", path.c_str());
}

} // namespace cmd
