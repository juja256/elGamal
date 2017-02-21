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
  L_NUMBER a,b,c,mu,p,s;
  l_init_by_len(&a, 128);
  l_init_by_len(&b, 128);
  l_init_by_len(&c, 128);
  l_init_by_str(&p, P);
  l_init_by_len(&mu, 256);
  l_init_by_len(&s, 256);
  a.words[0] = 436534564;
  a.words[1] = 23543;
  b.words[0] = 2;
  b.words[1] = 0;

  m_pre_barret(4, &p, &mu);
  l_pow(&a, 2, &s);
  l_dump(&s, 'h');
  m_pow(&a, &b, &p, &mu, &c);
  l_dump(&a, 'h');
  l_dump(&b, 'h');
  l_dump(&p, 'h');
  l_dump(&mu, 'h');
  l_dump(&c, 'h');
  return 0;
}
