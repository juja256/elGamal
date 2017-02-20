#ifndef BLOB_H
#define BLOB_H

class Blob {
public:
  union {
    char* data;
    unsigned char* bytes;
  };
  
  Blob();
  Blob(const char* text);
  Blob(const unsigned char* t, int size);
  Blob(int size);
  Blob(const Blob& b2);
  unsigned getSize();
  void operator=(const Blob& b2);
  void clear();
  Blob copy();
  ~Blob();
};

bool saveBlob(Blob& b, const char* fileName);
Blob loadBlob(const char *fileName);

#endif
