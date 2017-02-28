#ifndef ALGS_H
#define ALGS_H
#include "blob.h"
#include "long_ar.h"
#define P "0xAF5228967057FE1CB84B92511BE89A47"
#define Q "0x57A9144B382BFF0E5C25C9288DF44D23"
#define A "0x9E93A4096E5416CED0242228014B67B5"


class AlgsFactory {
  L_NUMBER p;
  L_NUMBER q;
  L_NUMBER d;
  L_NUMBER a;
  L_NUMBER mu1;
  L_NUMBER mu2;
  L_NUMBER seedL89;
public:
  AlgsFactory();
  ~AlgsFactory();
  u64 encryptBlockMysty4(u64 key, u64 block);
  Blob hashMerkleDamgard(Blob data);
  Blob signElGamal5(Blob key, Blob hash);
  Blob _signElGamal5Debug(Blob key, Blob hash, const char* fn);
  bool verifyElGamal5(Blob pub_key, Blob signature, Blob hash);
  Blob generateKeyElGamal5();
};

#endif
