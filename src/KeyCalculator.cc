#include "KeyCalculator.h"
#include "Decryptor.h"
#include "Euclidean.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <exception>

using namespace boost::multiprecision;

KeyCalculator::KeyCalculator(int256_t p, int256_t q, int256_t r)
    : p(0), q(0), m(0), phi_of_m(0), r(0), calculated(false) {
  try {
    setParameters(p, q, r);
    calcKeys();
  } catch (std::exception &e) {
    // std::cout << e.what();
    throw; // Rethrow exception.
  }
}

void KeyCalculator::setParameters(int256_t p, int256_t q, int256_t r) {
  this->p = p;
  this->q = q;
  this->r = r;
  this->m = p * q;
  this->phi_of_m = calcPhi(p, q);

  if (!isPrime(p) || !isPrime(q)) // p and q must be prime numbers
  {
    throw std::invalid_argument("[ERROR] p or q is not a prime number!");
  } else if ((r < m) && (r > 1) &&
             (Euclidean::euclidean(r, phi_of_m) !=
              1)) // r and phi of m must be coprime
  {
    throw std::invalid_argument("[ERROR] r is not equal or less than p * q (=> "
                                "m), or r and phi of m are not coprime!");
  }
}

void KeyCalculator::calcKeys() {
  if (calculated) {
    throw std::invalid_argument("[ERROR] Keys already calculated!");
  }

  calcPublicKey();
  calcPrivateKey();
  calculated = true;
}

void KeyCalculator::calcPrivateKey() {

  int256_t a = this->phi_of_m;
  int256_t b = this->r;

  int256_t s = 0;
  int256_t x = 0;

  // calculates the secret key
  Euclidean::extendedEuclidean(a, b, &x, &s);

  s = s < 0 ? makePositive(s, this->phi_of_m) : s;

  this->private_key = PrivateKey{s, this->p, this->q};
}

void KeyCalculator::calcPublicKey() {
  this->public_key = PublicKey{this->r, this->m};
}

bool KeyCalculator::isPrime(int256_t numb) {
  int it;
  for (it = 2; it < numb; it++) {
    if ((numb % it) == 0)
      return false;
  }

  return true;
}

int256_t KeyCalculator::calcPhi(int256_t a, int256_t b) {
  if (!isPrime(a) || !isPrime(b)) {
    return 0;
  }

  return (a - 1) * (b - 1);
}

int256_t KeyCalculator::makePositive(int256_t numb, int256_t mod) const {
  int256_t tmp = numb;
  while (tmp < 0) {
    tmp += mod;
  }

  return tmp;
}

std::pair<PublicKey, PrivateKey> KeyCalculator::getKeyPair() const{
  return {public_key, private_key};
}
