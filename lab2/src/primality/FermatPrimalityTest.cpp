#include "../../include/primality/FermatPrimalityTest.h"
#include "../../include/NumberTheoryService.h"

#include <cmath>

bool FermatPrimalityTest::TestOneRound(const BigInteger& n, const BigInteger& a) {
    return NumberTheoryService::modularExponentiation(a, n - 1, n) == 1;
}

int FermatPrimalityTest::CalculateIterationCount(double minimumProbability) {
    const double count =
        std::log(1.0 - minimumProbability) / std::log(0.5);

    return static_cast<int>(std::ceil(count));
}