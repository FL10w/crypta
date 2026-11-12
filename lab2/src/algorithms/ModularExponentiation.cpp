#include "../../include/algorithms/ModularExponentiation.h"
#include "../../include/algorithms/EuclideanGcd.h"
#include "../../include/algorithms/ExtendedEuclideanGcd.h"
#include "../../include/laba2.h"

BigInteger ModularExponentiation::calculate(BigInteger base, BigInteger exponent, BigInteger modulus) {
    if (modulus <= 0) throw Error::ERROR_INVALID_ARGUMENT;
    base %= modulus;
    if (base < 0) base += modulus;
    if (exponent < 0) {
        if (EuclideanGcd::calculate(base, modulus) != 1) {
            throw Error::ERROR_INVALID_ARGUMENT;
        }
        BezoutResult d = ExtendedEuclideanGcd::calculate(base, modulus);
        base = d.x % modulus;
        if (base < 0) base += modulus;
        exponent = -exponent;
    }
    BigInteger result = 1 % modulus;
    while (exponent > 0) {
        if (exponent % 2 == 1) result = result * base % modulus;
        base = base * base % modulus;
        exponent /= 2;
    }
    return result;
}