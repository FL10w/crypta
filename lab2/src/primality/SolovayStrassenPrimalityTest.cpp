#include "../../include/primality/SolovayStrassenPrimalityTest.h"
#include "../../include/NumberTheoryService.h"

#include <cmath>

bool SolovayStrassenPrimalityTest::TestOneRound(const BigInteger& n, const BigInteger& a) {
    const BigInteger result = NumberTheoryService::modularExponentiation(a, (n - 1) / 2, n);
    const int jacobi = NumberTheoryService::jacobiSymbol(a, n);

    if (jacobi == -1) {
        return result == n - 1;
    }

    if (jacobi == 1) {
        return result == 1;
    }

    return false;
}

int SolovayStrassenPrimalityTest::CalculateIterationCount(double minimumProbability) {
    const double count = std::log(1.0 - minimumProbability) / std::log(0.5);
    return static_cast<int>(std::ceil(count));
}