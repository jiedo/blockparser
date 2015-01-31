// Dump the transitive closure of a bunch of addresses
// g++ -I. -lcrypto show_script.cpp util.cpp sha256.cpp rmd160.cpp opcodes.cpp -o showscript

#include <util.h>
#include <common.h>
#include <errlog.h>
#include <option.h>
#include <rmd160.h>
#include <callback.h>

#include <string>
#include <vector>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(int args, char**argv)
{
  // uint8_t dst[20];
  // uint8_t src[] = "a2f58fcd3bd29caa9000d986e05eda2682662469";

  // fromHex(dst, src, 20, 0, 0);
  // showFullAddr(dst, true);

  uint8_t script[1024];

  int len = strlen(argv[1])/2;
  fromHex(script, (uint8_t *)argv[1], len, 0, 0);

  showScript(script,
             len,
             NULL,
             NULL);

}
