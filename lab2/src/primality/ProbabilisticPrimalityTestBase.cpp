
#include "../../include/primality/ProbabilisticPrimalityTestBase.h"

#include <cmath>
#include <random>

bool ProbabilisticPrimalityTestBase::IsProbablyPrime(
    const BigInteger& value,
    double minimumProbability
) {
    if (!std::isfinite(minimumProbability) || minimumProbability < 0.5 || minimumProbability >= 1.0) {  // isfinite - конечно число или нет
        throw Error::ERROR_INVALID_ARGUMENT;
    }

    if (value < 2) return false;
    if (value == 2 || value == 3) return true;
    if (value % 2 == 0) return false;

    const int iterations = CalculateIterationCount(minimumProbability);

    if (iterations <= 0) {
        throw Error::ERROR_INVALID_ARGUMENT;
    }

    std::random_device rd;
    std::mt19937_64 generator(rd());

    const BigInteger limit = value - 4; // у нас диапазон до n-2, мы хотим получить число offset и прибавить 2 (максимальное смещение) поэтому -4
    const unsigned int bitCount = boost::multiprecision::msb(limit) + 1; // сколько у нас битов в сгенерированном

    for (int i = 0; i < iterations; ++i) {
        BigInteger offset = limit + 1;

        while (offset > limit) {
            offset = 0;

            for (unsigned int j = 0; j < bitCount; ++j) {
                if (generator() & 1ULL) {   // проверка младшего бита
                    offset |= BigInteger(1) << j;
                }
            }
        }

        const BigInteger a = offset + 2;

        if (!TestOneRound(value, a)) {
            return false;
        }
    }
    return true;
}
