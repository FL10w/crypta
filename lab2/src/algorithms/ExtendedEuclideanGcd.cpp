#include "../../include/algorithms/ExtendedEuclideanGcd.h"
#include <utility>

BezoutResult ExtendedEuclideanGcd::calculate(BigInteger a, BigInteger b) {
    BigInteger oldR = a;
    BigInteger r = b;
    BigInteger oldX = 1;
    BigInteger x = 0;
    BigInteger oldY = 0;
    BigInteger y = 1;

    while (r != 0) {
        BigInteger q = oldR / r;
        BigInteger temp = oldR - q * r;
        oldR = r;
        r = temp;
        temp = oldX - q * x;
        oldX = x;
        x = temp;

        temp = oldY - q * y;
        oldY = y;
        y = temp;
    }

    if (oldR < 0) {
        oldR = -oldR;
        oldX = -oldX;
        oldY = -oldY;
    }
    return {oldR, oldX, oldY};
}