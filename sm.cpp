#include "eg.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sstream>

SignedMessage::SignedMessage() {}

SignedMessage::SignedMessage(const char* fileName) {
  FILE *f = fopen( fileName, "rb" );
  char fn[256];
  char s[1024];
  char h[1024];
  char y[1024];
  if (!fscanf(f, "file: %s\n"
            "hash_alg: %d\n"
            "signature_alg: %d\n"
            "pub_key: %s\n"
            "hash: %s\n"
            "signature: %s\n"
            "\n", fn, &hash_id, &alg_id, y, h, s)) {
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

Blob SignedMessage::getEncoded(const char* fn) {
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
                  "signature: %s\n\n\0", fn, this->hash_id, this->alg_id, c_, a_, b_);
  u32 header_size = strlen(header);
  Blob res(header_size + msg.getSize());
  memcpy(res.bytes, header, header_size);
  memcpy(res.bytes + header_size, msg.bytes, msg.getSize());
  return res;
}

bool SignedMessage::saveToFile(const char* fileName) {
  Blob data = this->getEncoded(fileName);
  FILE *f = fopen( fileName, "wb" );
  if( !f ) return false;
  bool success = ( fwrite( data.bytes, data.getSize(), 1, f ) != 0 );
  fclose( f );
  return success;
}

SignedMessage::~SignedMessage() {

}
