#include "algs.h"
#include "eg.h"
#include <time.h>
#include <stdlib.h>
#include "generators.h"
#include <string.h>
#include <stdio.h>

#define MSB13 0xFFF80000
#define HASH_ROUNDS 10

static u8 s_block[] = {
               0x63, 0xca, 0xb7, 0x04, 0x09, 0x53, 0xd0, 0x51, 0xcd, 0x60, 0xe0, 0xe7, 0xba, 0x70, 0xe1, 0x8c, 0x7c, 0x82, 0xfd, 0xc7,
               0x83, 0xd1, 0xef, 0xa3, 0x0c, 0x81, 0x32, 0xc8, 0x78, 0x3e, 0xf8, 0xa1, 0x77, 0xc9, 0x93, 0x23, 0x2c, 0x00, 0xaa, 0x40,
               0x13, 0x4f, 0x3a, 0x37, 0x25, 0xb5, 0x98, 0x89, 0x7b, 0x7d, 0x26, 0xc3, 0x1a, 0xed, 0xfb, 0x8f, 0xec, 0xdc, 0x0a, 0x6d,
               0x2e, 0x66, 0x11, 0x0d, 0xf2, 0xfa, 0x36, 0x18, 0x1b, 0x20, 0x43, 0x92, 0x5f, 0x22, 0x49, 0x8d, 0x1c, 0x48, 0x69, 0xbf,
               0x6b, 0x59, 0x3f, 0x96, 0x6e, 0xfc, 0x4d, 0x9d, 0x97, 0x2a, 0x06, 0xd5, 0xa6, 0x03, 0xd9, 0xe6, 0x6f, 0x47, 0xf7, 0x05,
               0x5a, 0xb1, 0x33, 0x38, 0x44, 0x90, 0x24, 0x4e, 0xb4, 0xf6, 0x8e, 0x42, 0xc5, 0xf0, 0xcc, 0x9a, 0xa0, 0x5b, 0x85, 0xf5,
               0x17, 0x88, 0x5c, 0xa9, 0xc6, 0x0e, 0x94, 0x68, 0x30, 0xad, 0x34, 0x07, 0x52, 0x6a, 0x45, 0xbc, 0xc4, 0x46, 0xc2, 0x6c,
               0xe8, 0x61, 0x9b, 0x41, 0x01, 0xd4, 0xa5, 0x12, 0x3b, 0xcb, 0xf9, 0xb6, 0xa7, 0xee, 0xd3, 0x56, 0xdd, 0x35, 0x1e, 0x99,
               0x67, 0xa2, 0xe5, 0x80, 0xd6, 0xbe, 0x02, 0xda, 0x7e, 0xb8, 0xac, 0xf4, 0x74, 0x57, 0x87, 0x2d, 0x2b, 0xaf, 0xf1, 0xe2,
               0xb3, 0x39, 0x7f, 0x21, 0x3d, 0x14, 0x62, 0xea, 0x1f, 0xb9, 0xe9, 0x0f, 0xfe, 0x9c, 0x71, 0xeb, 0x29, 0x4a, 0x50, 0x10,
               0x64, 0xde, 0x91, 0x65, 0x4b, 0x86, 0xce, 0xb0, 0xd7, 0xa4, 0xd8, 0x27, 0xe3, 0x4c, 0x3c, 0xff, 0x5d, 0x5e, 0x95, 0x7a,
               0xbd, 0xc1, 0x55, 0x54, 0xab, 0x72, 0x31, 0xb2, 0x2f, 0x58, 0x9f, 0xf3, 0x19, 0x0b, 0xe4, 0xae, 0x8b, 0x1d, 0x28, 0xbb,
               0x76, 0xc0, 0x15, 0x75, 0x84, 0xcf, 0xa8, 0xd2, 0x73, 0xdb, 0x79, 0x08, 0x8a, 0x9e, 0xdf, 0x16};

static u32 mystyRound(u32 k, u32 r) {
  u32 t = k^r;
  u8* b = (u8*)(&t);
  for (u32 i=0; i<4; i++)
    b[i] = s_block[b[i]];
  u32 m = (t & MSB13) >> 19;
  t <<= 13;
  t ^= m;
  return t;
}

AlgsFactory::AlgsFactory() {
  l_init_by_str(&p, P);
  l_init_by_str(&q, Q);
  l_init_by_str(&a, A);
  l_init_by_len(&mu1, 256);
  l_init_by_len(&mu2, 256);
  l_init_by_len(&seedL89, 128);
  ByteGenGenerateSequence(EmbededGenerator, NULL, (u8*)(seedL89.words), 128/8);
  seedL89.words[0] ^= (WORD)(&seedL89);
  seedL89.words[1] ^= (WORD)(this);

  m_pre_barret(2*p.len, &p, &mu1);
  m_pre_barret(2*q.len, &q, &mu2);
  l_init_by_len(&d, 128);
  d.words[0] = 2;
  l_sub(&q, &d, &d); //d=q-2
}

AlgsFactory::~AlgsFactory() {
  l_free(&mu1);
  l_free(&mu2);
  l_free(&p);
  l_free(&q);
  l_free(&d);
  l_free(&a);
  l_free(&seedL89);
}

u64 AlgsFactory::encryptBlockMysty4(u64 key, u64 block) {
  u32 L[5];
  u32 R[5];
  u32 K[4];
  K[0] = key & (u64)0xFFFFFFFF;
  K[1] = key & (((u64)0xFFFFFFFF) << 32);
  K[2] = ~K[1];
  K[3] = ~K[0];

  L[0] = block & (u64)0xFFFFFFFF;
  R[0] = (block & (((u64)0xFFFFFFFF) << 32)) >> 32;

  for (u32 i=1; i<=4; i++) {
    L[i] = mystyRound(K[i-1], R[i-1]) ^ L[i-1];
    R[i] = L[i-1];
  }
  u64 b=0;
  b ^= R[4];
  b ^= (u64)L[4]<<32;
  return b;
}

Blob AlgsFactory::hashMerkleDamgard(Blob data) {
  int size = data.getSize() / 8 + 1;
  u64* M = new u64[size];
  M[size-1] = 0;
  u64* H = new u64[size+1];
  H[0] = 0;
  memcpy((u8*)M, data.bytes, data.getSize());
  *((u8*)M + data.getSize()) = 1;
  for (u32 i=1; i<=size; i++) {
    H[i] = M[i-1] ^ H[i-1] ^ encryptBlockMysty4(H[i-1], M[i-1]);
  }
  Blob h(8);
  memcpy(h.bytes, (u8*)(&(H[size])), h.getSize());
  delete[] M;
  delete[] H;
  return h;
}

Blob AlgsFactory::signElGamal5(Blob key, Blob h) {
  L_NUMBER H, x, U, Z, UZ, k, g, S;
  l_init_by_len(&H, 128);
  l_init_by_len(&U, 128);
  l_init_by_len(&Z, 128);
  l_init_by_len(&UZ, 128);
  l_init_by_len(&k, 128);
  l_init_by_len(&g, 128);
  l_init_by_len(&S, 128);

  memcpy((u8*)(H.words), h.bytes, 8);
  H.words[1] = 0x00FFFFFFFFFFFF00;
  x.words = (WORD*)(key.bytes);
  x.len = key.getSize() / (ARCH/8);
  BitGenGenerateSequence(L89Generator, &seedL89, (u8*)(U.words), 128/8);
  m_pow(&a, &U, &p, &mu1, &Z); // Z = a^U mod p
  m_mul(&U, &Z, &q, &mu2, &UZ); // UZ = UZ mod q
  m_mul(&x, &H, &q, &mu2, &H); // H = xH mod q
  m_sub(&H, &Z, &q, &H); // H = H - Z mod q
  m_pow(&H, &d, &q, &mu2, &k); // k = H^(q-2) mod q
  m_mul(&k, &UZ, &q, &mu2, &k); // k = kUZ mod q
  m_pow(&Z, &d, &q, &mu2, &Z); // Z = Z^(q-2) mod q
  m_mul(&H, &Z, &q, &mu2, &g); // g = HZ mod q
  m_pow(&a, &g, &p, &mu1, &S); // S = a^g mod p
  Blob signature(32);
  memcpy(signature.bytes, (u8*)(k.words), 16);
  memcpy(signature.bytes + 16, (u8*)(S.words), 16);
  l_free(&H); l_free(&U); l_free(&Z); l_free(&UZ); l_free(&k); l_free(&g); l_free(&S);
  return signature;
}

bool AlgsFactory::verifyElGamal5(Blob pub_key, Blob signature, Blob hash) {
  L_NUMBER k, S, aS, y, H, Sp;
  l_init_by_len(&Sp, 128);
  l_init_by_len(&aS, 128);
  l_init_by_len(&y, 128);
  l_init_by_len(&H, 128);
  memcpy((u8*)(H.words), hash.bytes, 8); // H.words[0] = hash
  H.words[1] = 0x00FFFFFFFFFFFF00;
  H.len = 16 / (ARCH/8);
  memcpy((u8*)(y.words), pub_key.bytes, 16);
  k.words = (WORD*)(signature.bytes);
  k.len = 16 / (ARCH/8);
  S.words = (WORD*)(signature.bytes + 16);
  S.len = k.len;
  m_pow(&y, &H, &p, &mu1, &y); // y = y^H mod p
  m_mul(&a, &S, &p, &mu1, &aS); // aS = aS mod p
  m_pow(&S, &k, &p, &mu1, &Sp); // Sp = S^k mod p
  m_pow(&aS, &Sp, &p, &mu1, &aS); // aS = aS^Sp mod p
  bool r = !l_cmp(&aS, &y);
  l_free(&Sp); l_free(&aS); l_free(&y); l_free(&H);
  return r;
}

Blob AlgsFactory::generateKeyElGamal5() {
  L_NUMBER U, Y, Z;
  l_init_by_len(&U, 128);
  l_init_by_len(&Y, 128);
regen:
  BitGenGenerateSequence(L89Generator, &seedL89, (u8*)(U.words), 128/8);
  if (U.words[1] >= p.words[1]) goto regen;
  m_pow(&a, &U, &p, &mu1, &Y);

  Blob key(32);
  memcpy(key.bytes, (u8*)(U.words), 16);
  memcpy(key.bytes+16, (u8*)(Y.words), 16);

  l_free(&U); l_free(&Y);
  return key;
}
