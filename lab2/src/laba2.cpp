#include "../include/laba2.h"

bool isPrime(BigInteger p) {
    if (p < 2) return false;
    if (p == 2) return true;
    if (p % 2 == 0) return false;
    for (BigInteger i = 3; i <= p / i; i += 2) {
        if (p % i == 0) return false;
    }
    return true;
}