#include "eg.h"
#include "algs.h"
#include <string.h>
#include <stdio.h>

AbonentKeyStore::AbonentKeyStore() : size(0) {}

AbonentKeyStore::AbonentKeyStore(const char* keyFilePath) {} // TODO

int AbonentKeyStore::generateKey(u32 alg_id, int key_len) {
  Blob xy;
  AlgsFactory f;
  switch (alg_id) {
    case SIGN_EL_GAMAL_5:
      if (key_len != 128) throw CommonException(INVALID_KEY_LEN);
      if (size >= KEY_NUM) throw CommonException(KS_OVERFLOW);
      xy = f.generateKeyElGamal5();
      this->pr_key[this->size].key = Blob(xy.bytes, 16);
      this->pr_key[this->size].alg_id = SIGN_EL_GAMAL_5;
      this->pub_key[this->size].key = Blob(xy.bytes + 16, 16);
      this->pub_key[this->size].alg_id = SIGN_EL_GAMAL_5;
      size++;
    break;
    default:
      throw CommonException(UNKNOWN_ALG);
  }
  return size-1;
}

int AbonentKeyStore::deleteKey(u32 key_id) {
  if ((key_id >= size) || (this->pr_key[key_id].key.getSize() == 0))
    throw CommonException(KEY_NOT_FOUND);
  this->pr_key[key_id].key.clear();
  this->pub_key[key_id].key.clear();
  return 0;
}

SignedMessage AbonentKeyStore::sign(u32 key_id, u32 hash_id, Blob data) {
  if ((key_id >= size) || (this->pr_key[key_id].key.getSize() == 0))
    throw CommonException(KEY_NOT_FOUND);
  SignedMessage sm;
  Blob h, kS;
  AlgsFactory f;
  switch (hash_id) {
    case HASH_MERKLE_DAMGARD:
      if (this->pr_key[key_id].alg_id != SIGN_EL_GAMAL_5)
        throw CommonException(UNKNOWN_ALG);
      h = f.hashMerkleDamgard(data);
      kS = f.signElGamal5(this->pr_key[key_id].key, h);
      sm.hash = h;
      sm.signature = kS;
      sm.msg = data;
      sm.pub_key = this->pub_key[key_id].key.copy();
      sm.alg_id = SIGN_EL_GAMAL_5;
      sm.hash_id = HASH_MERKLE_DAMGARD;
    break;
    default:
      throw CommonException(UNKNOWN_ALG);
  }
  return sm;
}

PUBLIC_KEY AbonentKeyStore::getPublicKey(u32 key_id) {
  if ((key_id >= size) || (this->pr_key[key_id].key.getSize() == 0))
    throw CommonException(KEY_NOT_FOUND);
  PUBLIC_KEY k;
  k.alg_id = this->pub_key[key_id].alg_id;
  k.key = this->pub_key[key_id].key.copy();
  return k;
}

bool AbonentKeyStore::verify(SignedMessage& msg) {
  AlgsFactory f;
  if ((msg.alg_id != SIGN_EL_GAMAL_5) || (msg.hash_id != HASH_MERKLE_DAMGARD)) {
    throw CommonException(UNKNOWN_ALG);
  }
  Blob hash = f.hashMerkleDamgard(msg.msg);
  if (memcmp(hash.bytes, msg.hash.bytes, hash.getSize())) {
    throw CommonException(HASH_NOT_VALID);
  }
  return f.verifyElGamal5(msg.pub_key, msg.signature, hash);
}

AbonentKeyStore::~AbonentKeyStore() {

}
