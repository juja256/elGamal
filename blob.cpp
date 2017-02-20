#include "blob.h"
#include "long_ar.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct {
  unsigned ref_cnt;
  unsigned size;
} BLOB_HEADER;

static struct {
  BLOB_HEADER hdr;
  unsigned char data;
} emptyBlob = {{ 1,0 }, 0};

static int inc_ref_cnt(unsigned char* d) {
  ((BLOB_HEADER*)d - 1)->ref_cnt++;
  return ((BLOB_HEADER*)d - 1)->ref_cnt;
}

static int dec_ref_cnt(unsigned char* d) {
  ((BLOB_HEADER*)d - 1)->ref_cnt--;
  return ((BLOB_HEADER*)d - 1)->ref_cnt;
}

bool saveBlob(Blob& data, const char *fileName) {
  FILE *f = fopen(fileName, "wb");
  if (!f)  return false;
  bool success = (fwrite(data.bytes, data.getSize(), 1, f) != 0);
  fclose(f);
  return success;
}

Blob loadBlob(const char *fileName) {
  FILE *f = fopen(fileName, "rb");
  if (!f)  return Blob();
  fseek(f, 0, SEEK_END);
  long fileSize = ftell(f);
  fseek(f, 0, SEEK_SET);
  Blob res(fileSize);
  if (!fread(res.bytes, fileSize, 1, f))
    res = Blob();
  fclose(f);
  return res;
}

Blob::Blob() {
  this->bytes = &(emptyBlob.data);
  inc_ref_cnt(this->bytes);
}

Blob::Blob(const char* text) {
  u32 l = strlen(text);
  BLOB_HEADER* h = (BLOB_HEADER*)(new unsigned char[l + 1 + sizeof(BLOB_HEADER)]);
  h->size = l;
  h->ref_cnt = 1;
  this->bytes = (unsigned char*)(h + 1);
  strcpy(this->data, text);
  this->bytes[l] = 0;
}

Blob::Blob(const unsigned char* t, int size) {
  BLOB_HEADER* h = (BLOB_HEADER*)(new unsigned char[size + 1 + sizeof(BLOB_HEADER)]);
  h->size = size;
  h->ref_cnt = 1;
  this->bytes = (unsigned char*)(h + 1);
  memcpy(this->data, t, size);
  this->bytes[size] = 0;
}

Blob::Blob(int size) {
  BLOB_HEADER* h = (BLOB_HEADER*)(new unsigned char[size + 1 + sizeof(BLOB_HEADER)]);
  h->size = size;
  h->ref_cnt = 1;
  this->bytes = (unsigned char*)(h + 1);
  this->bytes[size] = 0;
}

Blob::Blob(const Blob& b2) {
  inc_ref_cnt(b2.bytes);
  this->data = b2.data;
}

void Blob::operator=(const Blob& b2) {
  inc_ref_cnt(b2.bytes);

  if (dec_ref_cnt(this->bytes) == 0) {
    delete[] (unsigned char*)((BLOB_HEADER*)(this->bytes) - 1);
  }
  
  this->data = b2.data;
}

void Blob::clear() {
  for (int i = 0; i < this->getSize(); i++) {
    this->bytes[i] = 0;
  }
}

Blob Blob::copy() {
  if (this->getSize())
  return Blob(this->bytes, this->getSize());
  else return Blob();
}

Blob::~Blob() {
  if (dec_ref_cnt(this->bytes) == 0) {
    delete[] (unsigned char*)((BLOB_HEADER*)(this->bytes) - 1);
  }
}

unsigned Blob::getSize() {
  return ((BLOB_HEADER*)(this->bytes) - 1)->size;
}