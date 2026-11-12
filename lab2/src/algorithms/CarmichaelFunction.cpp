#include "../../include/algorithms/CarmichaelFunction.h"
#include "../../include/algorithms/EuclideanGcd.h"

BigInteger CarmichaelFunction::calculate(BigInteger n) {
    if (n <= 0) throw Error::ERROR_INVALID_ARGUMENT;
    BigInteger result = 1;
    for (BigInteger p = 2; p <= n / p; p++) {
        int alpha = 0;
        BigInteger lambda = 0;
        while (n % p == 0) {
            n /= p;
            alpha++;
        }
        if (alpha == 0) continue;
        if (p == 2) {
            if (alpha == 1) lambda = 1;
            else if (alpha == 2) lambda = 2;
            else {
                lambda = 1;
                for (int i = 0; i < alpha - 2; i++) lambda *= 2;
            }
        }
        else {
            lambda = p - 1;
            for (int i = 0; i < alpha - 1; i++) lambda *= p;
        }
        result = result / EuclideanGcd::calculate(result, lambda) * lambda;
    }
    if (n > 1) {
        BigInteger lambda = n - 1;
        result = result / EuclideanGcd::calculate(result, lambda) * lambda;
    }
    return result;
}