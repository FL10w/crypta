#include "../../include/primality/MillerRabinPrimalityTest.h"
#include "../../include/NumberTheoryService.h"

#include <cmath>

bool MillerRabinPrimalityTest::TestOneRound(const BigInteger& n, const BigInteger& a) {
    BigInteger d = n - 1;
    int s = 0;

    while (d % 2 == 0) {
        d /= 2;
        ++s;
    }
    
    BigInteger x = NumberTheoryService::modularExponentiation(a, d, n);

    if (x == 1 || x == n - 1) {
        return true;
    }

    for (int i = 1; i < s; ++i) {
        x = (x * x) % n;

        if (x == n - 1) {
            return true;
        }
    }
    return false;
}

int MillerRabinPrimalityTest::CalculateIterationCount(double minimumProbability) {
    const double count = std::log(1.0 - minimumProbability) / std::log(0.25);
    return static_cast<int>(std::ceil(count));
}