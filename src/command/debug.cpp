#include <cstdio>
#include <vector>
#include <string>
#include <cstdint>

#include "zdb_backend.h"        
#include "zdb_cmd.h"

namespace cmd {

void halt()  { zdb::halt();  std::puts("HALT OK"); }
void cont()  { zdb::cont();  std::puts("CONT OK"); }
void init(unsigned csu_id){
 if(zdb::init(csu_id))
     std::puts("INIT OK");
 else
     std::puts("INIT FAIL");
 
};
void step(unsigned n) {
  if (n == 0) n = 1;
  zdb::step(n);
  std::printf("STEP OK pc=0x%llx\n", (unsigned long long)zdb::show_pc());
}

void step(const std::vector<std::string>& /*args*/) {

  step(1);
}

void stepl(unsigned n) {
  if (n == 0) n = 1;
  zdb::stepl(n);
}

void run()   { zdb::run();   std::puts("RUN"); }
void reset() { zdb::reset();
               std::puts("RESET (stub)"); }


} // namespace cmd
