#include "eg.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sstream>

SignedExtendedMessage::SignedExtendedMessage() {}
SignedBasicMessage::SignedBasicMessage() {}

SignedExtendedMessage::SignedExtendedMessage(const char* fileName) {
  FILE *f = fopen( fileName, "rb" );
  //char fn[256];
  char s[1024];
  char h[1024];
  char y[1024];
  fn = Blob("noname");
  if (!fscanf(f, 
            "file: %s\n"
            "hash_alg: %d\n"
            "signature_alg: %d\n"
            "pub_key: %s\n"
            "hash: %s\n"
            "signature: %s\n"
            "\n", fn.data, &hash_id, &alg_id, y, h, s)) {
    throw CommonException(READ_FILE_ERR);
  }
  u32 header_size = ftell(f);

  fseek( f, 0, SEEK_END );
  u32 msg_size = ftell(f) - header_size;
  fseek(f, header_size, SEEK_SET);
  this->msg = Blob(msg_size);
  if ( !fread( msg.bytes, msg_size, 1, f ) ) {
    fclose(f);
    throw CommonException(READ_FILE_ERR);
  }
  L_NUMBER S, H, Y;
  l_init_by_str(&S, s);
  l_init_by_str(&H, h);
  l_init_by_str(&Y, y);

  this->hash = Blob((u8*)(H.words), H.len * (ARCH/8));
  this->signature = Blob((u8*)(S.words), S.len * (ARCH/8));
  this->pub_key = Blob((u8*)(Y.words), Y.len * (ARCH/8));

  l_free(&S); l_free(&H); l_free(&Y);
  fclose(f);
}

SignedBasicMessage::SignedBasicMessage(const char* fileName) { /*disgusting...*/
  FILE *f = fopen(fileName, "rb");
  fn = Blob(256);
  char h[1024];
  char y[1024];
  char k_[1024]; 
  char S_[1024];

  if (!fscanf(f,
    "------------------------------\n"
    "%s\n"
    "H = %s\n"
    "Y = %s\n"
    "K = %s\n"
    "S = %s\n"
    "------------------------------", fn.data, h, y, k_, S_)) {
    throw CommonException(READ_FILE_ERR);
  }

  this->hash = Blob(8);
  this->pub_key = Blob(16);
  this->k = Blob(16);
  this->S = Blob(16);

  char* h_ = h;
  for (u32 i = 0; i < 8; i++) {
    sscanf(h_, "%02hhx", &(this->hash.bytes[i]));
    h_ += 2;
  }
  h_ = y;
  for (u32 i = 0; i < 16; i++) {
    sscanf(h_, "%02hhx", &(this->pub_key.bytes[i]));
    h_ += 2;
  }
  h_ = k_;

  for (int i = 15; i >= 0; i--) {
    sscanf(h_, "%02hhx", &(this->k.bytes[i]));
    h_ += 2;
  }

  h_ = S_;
  for (int i = 15; i >= 0; i--) {
    sscanf(h_, "%02hhx", &(this->S.bytes[i]));
    h_ += 2;
  }

  fclose(f);
}

Blob SignedExtendedMessage::getEncoded() {
  char a_[1024];
  char* a = a_;
  a[0]='0'; a[1]='x'; a+=2;
  u8* h = hash.bytes + hash.getSize() - 1;
  for (u32 i=0; i<hash.getSize(); i++) {
    a += sprintf(a, "%02X", *h);
    h--;
  }
  *a = '\0';

  char b_[1024];
  char* b = b_;
  b[0]='0'; b[1]='x'; b+=2;
  h = signature.bytes + signature.getSize() - 1;
  for (u32 i=0; i<signature.getSize(); i++) {
    b += sprintf(b, "%02X", *h);
    h--;
  }
  *b = '\0';

  char c_[1024];
  char* c = c_;
  c[0]='0'; c[1]='x'; c+=2;
  h = pub_key.bytes + pub_key.getSize() - 1;
  for (u32 i=0; i<pub_key.getSize(); i++) {
    c += sprintf(c, "%02X", *h);
    h--;
  }
  *c = '\0';

  char header[4096];
  sprintf(header, "file: %s\n"
                  "hash_alg: %d\n"
                  "signature_alg: %d\n"
                  "pub_key: %s\n"
                  "hash: %s\n"
                  "signature: %s\n\n\0", fn.data, this->hash_id, this->alg_id, c_, a_, b_);
  u32 header_size = strlen(header);
  Blob res(header_size + msg.getSize());
  memcpy(res.bytes, header, header_size);
  memcpy(res.bytes + header_size, msg.bytes, msg.getSize());
  return res;
}

Blob SignedBasicMessage::getEncoded() {
  char a_[1024];
  char* a = a_;
  u8* h = hash.bytes;
  for (u32 i = 0; i<hash.getSize(); i++) {
    a += sprintf(a, "%02x", *h);
    h++;
  }
  *a = '\0';

  char b_[1024];
  char* b = b_;
  h = S.bytes + S.getSize() - 1;
  for (u32 i = 0; i<S.getSize(); i++) {
    b += sprintf(b, "%02x", *h);
    h--;
  }
  *b = '\0';

  char d_[1024];
  char* d = d_;
  h = k.bytes + k.getSize() - 1;
  for (u32 i = 0; i<k.getSize(); i++) {
    d += sprintf(d, "%02x", *h);
    h--;
  }
  *d = '\0';

  char c_[1024];
  char* c = c_;
  h = pub_key.bytes;
  for (u32 i = 0; i<pub_key.getSize(); i++) {
    c += sprintf(c, "%02x", *h);
    h++;
  }
  *c = '\0';

  char header[4096];
  const char* fmt =
    "------------------------------\n"
    "%s\n"
    "H = %s\n"
    "Y = %s\n"
    "K = %s\n"
    "S = %s\n"
    "------------------------------\0";
  sprintf(header, fmt, fn.data, a_, c_, d_, b_);
  Blob res(header);
  return res;
}

bool SignedMessage::saveToFile(const char* fileName) {
  Blob data = this->getEncoded();
  FILE *f = fopen(fileName, "wb");
  if (!f) return false;
  bool success = (fwrite(data.bytes, data.getSize(), 1, f) != 0);
  fclose(f);
  return success;
}

SignedMessage::~SignedMessage() {}

Blob SignedMessage::getEncoded() { return Blob(); }

SignedBasicMessage::~SignedBasicMessage() {

}

SignedExtendedMessage::~SignedExtendedMessage() {

}
