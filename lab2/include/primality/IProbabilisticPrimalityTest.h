#pragma once

#include "../laba2.h"

class IProbabilisticPrimalityTest {
public:
    virtual bool IsProbablyPrime(const BigInteger& value, double minimumProbability) = 0;
    
    virtual ~IProbabilisticPrimalityTest() = default;
};