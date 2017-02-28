#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "eg.h"
#include "algs.h"
#include "long_ar.h"
#include <string>

void test() {
  bool t = 0, v = 0;
  AlgsFactory f;
  const char* msg = "1212";
  Blob b1(msg);
  Blob b2 = loadBlob("test.txt");
  Blob b3("");
  Blob h1 = f.hashMerkleDamgard(b3);
  printf(HEX_FORMAT"\n", *((WORD*)(h1.bytes)));

  AbonentKeyStore ks;
  int key1 = ks.generateKey(SIGN_EL_GAMAL_5, 128);
  SignedBasicMessage cms = ks.signBasic(key1, HASH_MERKLE_DAMGARD, "test.txt");
  cms.saveToFile("test.sig");
  try {
    v = ks.verify(cms, b2, HASH_MERKLE_DAMGARD, SIGN_EL_GAMAL_5);
  }
  catch (...) {
    printf("Verification error\n");
  }
  SignedBasicMessage cms_("test.sig");
  printf("%s\n", cms.getEncoded().data);
  printf("%s\n", cms_.getEncoded().data);
  try {
    t = ks.verify(cms_, b2, HASH_MERKLE_DAMGARD, SIGN_EL_GAMAL_5);
  }
  catch (...) {
    printf("Verification error\n");
  }
  printf("Verification statuses: %d %d\n", v, t);
}

int main(int argc, char const *argv[]) {
  if (argc < 3)
    return 1;

  if (!strcmp(argv[1], "-sign")) {
    AbonentKeyStore ks;
    int key1 = ks.generateKey(SIGN_EL_GAMAL_5, 128);
    SignedBasicMessage cms = ks.signBasic(key1, HASH_MERKLE_DAMGARD, argv[2]);
    std::string fn = std::string(argv[2]) + std::string(".sig");
    if (!cms.saveToFile(fn.c_str())) {
      return 2;
    }
    printf("sign OK\n");
  }
  else if (!strcmp(argv[1], "-check")) {
    bool r;
    if (argc < 4)
      return 1;
    AbonentKeyStore ks;
    Blob msg = loadBlob(argv[2]);
    SignedBasicMessage cms(argv[3]);
    try {
      r = ks.verify(cms, msg, HASH_MERKLE_DAMGARD, SIGN_EL_GAMAL_5);
      if (r) printf("check OK\n");
      else printf("check NOK\n");
    }
    catch (...) {
      printf("check NOK\n");
    }
    
  }
  return 0;
}
