#include <iostream>
#include "zdb_backend.h"
#include "config.h"
int run_repl(); // from repl.cpp

int main(int argc, char** argv){
  (void)argc; (void)argv;
  if (!zdb::init(0)) { std::cerr << "init failed\n"; return 1; }

#if DEVPORT(LINUX)
  std::cout << "ZDB (mock) – type 'help' for commands.\n";
#elif DEVPORT(FPGA)
  std::cout << "ZDB (real) – type 'help' for commands.\n";
#else 
  std::cout << "ZDB (unknown backend)\n";
#endif

  int rc = run_repl();
  zdb::shutdown();
  return rc;
}
