#pragma once
#include "../laba2.h"

struct BezoutResult {
    BigInteger gcd;
    BigInteger x;
    BigInteger y;
};

class ExtendedEuclideanGcd {
public:
    static BezoutResult calculate(BigInteger a, BigInteger b);
};