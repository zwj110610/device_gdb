#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <utility>
#include <algorithm>

#include "zdb_backend.h"
#include "zdb_cmd.h"
#include "elf_loader.h"

#if DEVPORT(LINUX)
#include <sys/ptrace.h>
#include <sys/user.h>
#endif



namespace cmd {

void symbols(){ zdb::cmd_symbols_backend(); }

void print_var(const std::string& name, size_t size){ zdb::cmd_print_var_backend(name, size); }

void watch_add(const std::string& name, size_t size){ zdb::cmd_watch_add_backend(name, size); }

void watch_del(const std::string& name){ zdb::cmd_watch_del_backend(name); }

void watch_ls(){ zdb::cmd_watch_ls_backend(); }

void watch_poll(){ zdb::cmd_watch_poll_backend(); }

} // namespace cmd
