#pragma once
#include "../laba2.h"

class EulerFunction {
public:
    static BigInteger byDefinition(BigInteger n);
    static BigInteger byPrimeFactorization(BigInteger n);
    static BigInteger byFourierTransform(BigInteger n);
};