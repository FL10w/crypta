#include "../../include/algorithms/EuclideanGcd.h"
#include "../../include/laba2.h"

BigInteger EuclideanGcd::calculate(BigInteger a, BigInteger b) {
    while (a != 0) {
        BigInteger remainder = b % a;
        b = a;
        a = remainder;
    }

    return b < 0 ? -b : b;
}