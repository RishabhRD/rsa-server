#pragma once
#include "types.h"
#include <string>


class Decryptor {
private:
  const PrivateKey private_key;
  std::string text;

public:
  Decryptor(const PrivateKey key);

  std::string decryptString(CryptoString input);

  char decryptChar(CryptoChar c) const;
};
