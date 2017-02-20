#ifndef EG_H
#define EG_H
#include "long_ar.h"
#include "blob.h"

#define ENC_MYSTY_4_RND     0x00000100
#define HASH_MERKLE_DAMGARD 0x00000010
#define SIGN_EL_GAMAL_5     0x00000001
#define KEY_NUM 6

#define UNKNOWN_ALG 1
#define READ_FILE_ERR 2
#define INVALID_KEY_LEN 3
#define KS_OVERFLOW 4
#define KEY_NOT_FOUND 5
#define HASH_NOT_VALID 6

typedef struct {
  u32 alg_id;
  Blob key;
} PRIVATE_KEY;

typedef struct {
  u32 alg_id;
  Blob key;
} PUBLIC_KEY;

class CommonException {
  int code;
public:
  CommonException(int c):code(c) {}
  int getCode() { return this->code; }
  ~CommonException() {}
};

/* Signed Message Format
file: cms.sig
hash_alg: 16
signature_alg: 1
pub_key: 0x2233123425AB234...
hash: 0x114353453453454...
signature: 0x112342554436...

Lorem ipsum...
*/
class SignedMessage {
public:
  u32 alg_id;
  u32 hash_id;
  Blob msg;
  Blob hash;
  Blob signature;
  Blob pub_key;
  SignedMessage();
  SignedMessage(const char* fileName);
  Blob getEncoded(const char* fileName);
  bool saveToFile(const char* fileName);
  ~SignedMessage();
};

class AbonentKeyStore {
  PRIVATE_KEY pr_key[KEY_NUM];
  PUBLIC_KEY pub_key[KEY_NUM];
  int size;
public:
  AbonentKeyStore();
  AbonentKeyStore(const char* keyFilePath);
  int generateKey(u32 alg_id, int key_len);
  int deleteKey(u32 i);
  SignedMessage sign(u32 key_id, u32 hash_id, Blob data);
  PUBLIC_KEY getPublicKey(u32 key_id);
  bool verify(SignedMessage& msg);
  ~AbonentKeyStore();
};

#endif
