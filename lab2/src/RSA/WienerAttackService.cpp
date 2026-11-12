#include "../../include/rsa/WienerAttackService.h"


WienerAttackResult WienerAttackService::attack(const BigInteger& n, const BigInteger& e)
{
    if (n <= 0 || e <= 0) {
        throw Error::ERROR_INVALID_ARGUMENT;
    }

    WienerAttackResult result;
    BigInteger numerator = e;
    BigInteger denominator = n;
    BigInteger p0 = 0, p1 = 1;
    BigInteger q0 = 1, q1 = 0;

    while (denominator != 0) {
        BigInteger a = numerator / denominator;
        BigInteger remainder = numerator % denominator;
        BigInteger p = a * p1 + p0;
        BigInteger q = a * q1 + q0;

        result.convergents.push_back({p, q});

        p0 = p1;
        p1 = p;
        q0 = q1;
        q1 = q;
        numerator = denominator;
        denominator = remainder;
    }

    for (const WienerConvergent& convergent : result.convergents) {
        BigInteger k = convergent.numerator;
        BigInteger d = convergent.denominator;

        if (k == 0 || d == 0) continue;

        BigInteger edMinusOne = e * d - 1;
        if (edMinusOne % k != 0) continue;

        BigInteger phi = edMinusOne / k;
        BigInteger sumPQ = n - phi + 1;
        BigInteger discriminant = sumPQ * sumPQ - 4 * n;

        if (discriminant < 0) continue;

        BigInteger root = boost::multiprecision::sqrt(discriminant);
        if (root * root != discriminant || (sumPQ + root) % 2 != 0) continue;

        BigInteger prime1 = (sumPQ + root) / 2;
        BigInteger prime2 = (sumPQ - root) / 2;

        if (prime1 > 0 && prime2 > 0 && prime1 * prime2 == n) {
            result.success = true;
            result.privateExponent = d;
            result.eulerFunction = phi;
            return result;
        }
    }

    return result;
}