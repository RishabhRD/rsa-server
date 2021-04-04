#include "types.h"
#include <boost/multiprecision/cpp_int.hpp>
using namespace boost::multiprecision;
using std::string;
class KeyCalculator {
private:
  int256_t p;
  int256_t q;
  int256_t phi_of_m;

  int256_t m;
  int256_t r;
  bool calculated;

  PrivateKey private_key;
  PublicKey public_key;

  void calcPublicKey();
  void calcPrivateKey();

  int256_t makePositive(int256_t numb, int256_t mod) const;

  void setParameters(int256_t p, int256_t q, int256_t r);

  void calcKeys();

  static bool isPrime(int256_t numb);

  static int256_t calcPhi(int256_t a, int256_t b);

public:
  KeyCalculator() = delete;
  KeyCalculator(int256_t p, int256_t q, int256_t r);
  std::pair<PublicKey, PrivateKey> getKeyPair() const;
};
