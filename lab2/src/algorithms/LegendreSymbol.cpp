#include "../../include/algorithms/LegendreSymbol.h"
#include "../../include/algorithms/JacobiSymbol.h"
#include "../../include/laba2.h"

int LegendreSymbol::calculate(BigInteger a, BigInteger p) {
    if (!isPrime(p)) throw Error::ERROR_INVALID_PRIME;
    return JacobiSymbol::calculate(a, p);
}