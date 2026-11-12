#include "../include/NumberTheoryService.h"
#include "../include/algorithms/LegendreSymbol.h"
#include "../include/algorithms/JacobiSymbol.h"
#include "../include/algorithms/EuclideanGcd.h"
#include "../include/algorithms/ExtendedEuclideanGcd.h"
#include "../include/algorithms/BinaryEuclideanGcd.h"
#include "../include/algorithms/ModularExponentiation.h"
#include "../include/algorithms/EulerFunction.h"
#include "../include/algorithms/CarmichaelFunction.h"

int NumberTheoryService::legendreSymbol(BigInteger a, BigInteger p) {
    return LegendreSymbol::calculate(a, p);
}

int NumberTheoryService::jacobiSymbol(BigInteger a, BigInteger n) {
    return JacobiSymbol::calculate(a, n);
}

BigInteger NumberTheoryService::gcd(BigInteger a, BigInteger b) {
    return EuclideanGcd::calculate(a, b);
}

BezoutResult NumberTheoryService::extendedGcd(BigInteger a, BigInteger b) {
    return ExtendedEuclideanGcd::calculate(a, b);
}

BigInteger NumberTheoryService::binaryGcd(BigInteger a, BigInteger b) {
    return BinaryEuclideanGcd::calculate(a, b);
}

BigInteger NumberTheoryService::modularExponentiation(
    BigInteger base, BigInteger exponent, BigInteger modulus
) {
    return ModularExponentiation::calculate(base, exponent, modulus);
}

BigInteger NumberTheoryService::eulerByDefinition(BigInteger n) {
    return EulerFunction::byDefinition(n);
}

BigInteger NumberTheoryService::eulerByPrimeFactorization(BigInteger n) {
    return EulerFunction::byPrimeFactorization(n);
}

BigInteger NumberTheoryService::eulerByFourierTransform(BigInteger n) {
    return EulerFunction::byFourierTransform(n);
}

BigInteger NumberTheoryService::carmichael(BigInteger n) {
    return CarmichaelFunction::calculate(n);
}