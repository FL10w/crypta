#include "../../include/rsa/RSAService.h"

#include "../../include/primality/FermatPrimalityTest.h"
#include "../../include/primality/SolovayStrassenPrimalityTest.h"
#include "../../include/primality/MillerRabinPrimalityTest.h"
#include "../../include/NumberTheoryService.h"
#include "../../include/algorithms/ExtendedEuclideanGcd.h"

#include <random>
#include <cstdint>
#include <stdexcept>

RSAService::KeyGenerator::KeyGenerator(
    PrimalityTestType testType,
    double minimumProbability,
    unsigned int bitLength
)
    : testType(testType),
      minimumProbability(minimumProbability),
      bitLength(bitLength)
{
    if (minimumProbability < 0.5 || minimumProbability >= 1.0) {
        throw Error::ERROR_INVALID_ARGUMENT;
    }

    if (bitLength < 16) {
        throw Error::ERROR_INVALID_ARGUMENT;
    }

    switch (testType) {
    case PrimalityTestType::Fermat:
        primalityTest = std::make_unique<FermatPrimalityTest>();
        break;

    case PrimalityTestType::SolovayStrassen:
        primalityTest =
            std::make_unique<SolovayStrassenPrimalityTest>();
        break;

    case PrimalityTestType::MillerRabin:
        primalityTest = std::make_unique<MillerRabinPrimalityTest>();
        break;

    default:
        throw Error::ERROR_INVALID_ARGUMENT;
    }
}

RSAService::RSAService(
    PrimalityTestType testType,
    double minimumProbability,
    unsigned int bitLength
)
    : keyGenerator(testType, minimumProbability, bitLength)
{
}

static BigInteger generateRandomCandidate(
    unsigned int bitLength,
    std::mt19937_64& generator
)
{
    BigInteger candidate = 0;
    for (unsigned int i = 0; i < bitLength; ++i) {
        if ((generator() & 1ULL) != 0) {
            candidate |= BigInteger(1) << i;
        }
    }
    candidate |= BigInteger(1) << (bitLength - 1); // страший бит 1, чтобы точно была заданная длина
    candidate |= 1; // число чтобы было нечетным, в конец 1
    return candidate;
}

static BigInteger generatePrime(
    unsigned int bitLength,
    double minimumProbability,
    IProbabilisticPrimalityTest& primalityTest,
    std::mt19937_64& generator
)
{
    while (true) {
        BigInteger candidate = generateRandomCandidate(bitLength, generator);

        if (primalityTest.IsProbablyPrime(candidate, minimumProbability)) {
            return candidate;
        }
    }
}

RSAKeyPair RSAService::KeyGenerator::generateKeyPair()
{
    std::random_device rd;
    std::mt19937_64 generator(rd());
    while (true) {
        BigInteger p = generatePrime(bitLength, minimumProbability, *primalityTest, generator);
        BigInteger q;
        while (true) {
            q = generatePrime(bitLength, minimumProbability, *primalityTest, generator);
            if (q != p) { break; }
        }

        BigInteger difference = (p > q) ? p - q : q - p;
        BigInteger minimumDifference = BigInteger(1) << (bitLength - 16);
        if (difference < minimumDifference) {
            continue;
        }
        BigInteger n = p * q;
        BigInteger phi = (p - 1) * (q - 1);
        BigInteger e = 65537;
        if (NumberTheoryService::gcd(e, phi) != 1) {
            continue;
        }
        BezoutResult result = NumberTheoryService::extendedGcd(e, phi);
        BigInteger d = result.x % phi;
        if (d < 0) {
            d += phi;
        }
        BigInteger threeD = 3 * d;
        if (threeD * threeD * threeD * threeD < n) {
            continue;
        }
        return RSAKeyPair{n, e, d};
    }
}

RSAKeyPair RSAService::generateKeyPair()
{
    return keyGenerator.generateKeyPair();
}

BigInteger RSAService::encrypt(const BigInteger& message, const RSAKeyPair& keyPair) const
{
    if (message < 0 || message >= keyPair.n) {
        throw Error::ERROR_INVALID_ARGUMENT;
    }
    return NumberTheoryService::modularExponentiation(message, keyPair.e, keyPair.n);
}

BigInteger RSAService::decrypt(const BigInteger& ciphertext, const RSAKeyPair& keyPair) const
{
    if (ciphertext < 0 || ciphertext >= keyPair.n) {
        throw Error::ERROR_INVALID_ARGUMENT;
    }
    return NumberTheoryService::modularExponentiation(ciphertext, keyPair.d, keyPair.n);
}