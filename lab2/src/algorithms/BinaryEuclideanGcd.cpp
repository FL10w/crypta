#include "../../include/algorithms/BinaryEuclideanGcd.h"
#include <utility>

BigInteger BinaryEuclideanGcd::calculate(BigInteger a, BigInteger b) {
    a = boost::multiprecision::abs(a);
    b = boost::multiprecision::abs(b);

    if (a == 0) return b;
    if (b == 0) return a;

    unsigned int shift = 0;

    while (a % 2 == 0 && b % 2 == 0) {
        a /= 2;
        b /= 2;
        ++shift;
    }
    while (a % 2 == 0) { a /= 2; }
    while (b != 0){
        while (b % 2 == 0) { b /= 2; }
        if (a > b) std::swap(a, b);
        b -= a;
    }
    return a << shift;
}