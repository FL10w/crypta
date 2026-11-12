#include "../../include/algorithms/JacobiSymbol.h"
#include "../../include/laba2.h"
#include <utility>

int JacobiSymbol::calculate(BigInteger a, BigInteger n) {
    if (n <= 1 || n % 2 == 0) { throw Error::ERROR_INVALID_ARGUMENT; }
    a %= n;
    if (a < 0) { a += n; }
    int s = 1;
    while (a != 0) {
        while (a % 2 == 0) {
            a /= 2;
            BigInteger remainder = n % 8;
            if (remainder == 3 || remainder == 5) { s = -s; }
        }

        std::swap(a, n);
        if (a % 4 == 3 && n % 4 == 3) { s = -s; }
        a %= n;
    }
    return n == 1 ? s : 0;
}