#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "eg.h"
#include "algs.h"
#include "long_ar.h"

int main(int argc, char const *argv[]) {
  AlgsFactory f;
  const char* msg = "1212";
  Blob b1(msg);
  Blob b2 = loadBlob("test.txt");

  Blob h1 = f.hashMerkleDamgard(b1);
  //printf(HEX_FORMAT "\n", *((WORD*)(h1.bytes)));
  Blob h2 = f.hashMerkleDamgard(b2);
  printf(HEX_FORMAT " " HEX_FORMAT "\n", *((WORD*)(h1.bytes)), *((WORD*)(h2.bytes)));

  AbonentKeyStore ks;
  int key1 = ks.generateKey(SIGN_EL_GAMAL_5, 128);
  SignedMessage cms = ks.sign(key1, HASH_MERKLE_DAMGARD, b1);
  cms.saveToFile("test.sig");
  bool v = ks.verify(cms);
  SignedMessage cms_("test.sig");
  printf("%s\n", cms_.getEncoded("test.sig").data);
  bool t = ks.verify(cms_);
  printf("Verification statuses: %d %d\n", v, t);
  return 0;
}
