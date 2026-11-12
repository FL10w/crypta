#pragma once

#include "laba2.h"
#include "algorithms/ExtendedEuclideanGcd.h"

class NumberTheoryService {
public:
    static int legendreSymbol(BigInteger a, BigInteger p);
    static int jacobiSymbol(BigInteger a, BigInteger n);

    static BigInteger gcd(BigInteger a, BigInteger b);
    static BezoutResult extendedGcd(BigInteger a, BigInteger b);
    static BigInteger binaryGcd(BigInteger a, BigInteger b);

    static BigInteger modularExponentiation(
        BigInteger base,
        BigInteger exponent,
        BigInteger modulus
    );

    static BigInteger eulerByDefinition(BigInteger n);
    static BigInteger eulerByPrimeFactorization(BigInteger n);
    static BigInteger eulerByFourierTransform(BigInteger n);

    static BigInteger carmichael(BigInteger n);
};