#include "../../include/algorithms/EulerFunction.h"
#include "../../include/algorithms/EuclideanGcd.h"
#include <cmath>
#include <numbers>

BigInteger EulerFunction::byDefinition(BigInteger n) {
    if (n <= 0) throw Error::ERROR_INVALID_ARGUMENT;
    BigInteger result = 0;
    for (BigInteger i = 1; i <= n; ++i) {
        if (EuclideanGcd::calculate(i, n) == 1) {
            ++result;
        }
    }
    return result;
}

BigInteger EulerFunction::byPrimeFactorization(BigInteger n) {
    if (n <= 0) throw Error::ERROR_INVALID_ARGUMENT;
    BigInteger result = n;
    for (BigInteger p = 2; p <= n / p; p++) {
        if (n % p == 0) {
            result -= result / p;
            while (n % p == 0) {
                n /= p;
            }
        }
    }
    if (n > 1) result -= result / n;
    return result;
}

BigInteger EulerFunction::byFourierTransform(BigInteger n) {
    if (n <= 0) throw Error::ERROR_INVALID_ARGUMENT;
    long double result = 0;
    for (BigInteger k = 1; k <= n; k++) {
        long double alpha = 2 * std::numbers::pi_v<long double> * (long double)k / (long double)n;
        result += (long double)EuclideanGcd::calculate(k, n) * std::cos(alpha);
    }
    return (BigInteger)std::round(result);
}