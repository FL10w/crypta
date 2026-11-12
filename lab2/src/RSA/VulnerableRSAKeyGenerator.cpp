#include "../../include/rsa/VulnerableRSAKeyGenerator.h"
#include "../../include/NumberTheoryService.h"
#include "../../include/primality/FermatPrimalityTest.h"
#include "../../include/primality/SolovayStrassenPrimalityTest.h"
#include "../../include/primality/MillerRabinPrimalityTest.h"

#include <random>
#include <cmath>

static BigInteger generateRandomNumber(unsigned int bitLength, std::mt19937_64& generator) {
    BigInteger number = 0;
    for (unsigned int i = 0; i < bitLength; ++i) {
        number <<= 1;
        number |= generator() & 1;
    }
    number |= BigInteger(1) << (bitLength - 1);
    number |= 1;
    return number;
}

static BigInteger generatePrime(unsigned int bitLength, std::mt19937_64& generator, IProbabilisticPrimalityTest& primalityTest, double minimumProbability) {
    while (true) {
        BigInteger candidate = generateRandomNumber(bitLength, generator);
        if (primalityTest.IsProbablyPrime(candidate, minimumProbability)) return candidate;
    }
}

WienerVulnerableKeyGenerator::WienerVulnerableKeyGenerator(RSAService::PrimalityTestType testType, double minimumProbability)
    : testType(testType), minimumProbability(minimumProbability) {
    switch (testType) {
    case RSAService::PrimalityTestType::Fermat:
        primalityTest = std::make_unique<FermatPrimalityTest>();
        break;
    case RSAService::PrimalityTestType::SolovayStrassen:
        primalityTest = std::make_unique<SolovayStrassenPrimalityTest>();
        break;
    case RSAService::PrimalityTestType::MillerRabin:
        primalityTest = std::make_unique<MillerRabinPrimalityTest>();
        break;
    default:
        throw Error::ERROR_INVALID_ARGUMENT;
    }
}

RSAKeyPair WienerVulnerableKeyGenerator::generate(unsigned int bitLength) {
    if (bitLength < 8) throw Error::ERROR_INVALID_ARGUMENT;

    std::random_device randomDevice;
    std::mt19937_64 generator(randomDevice());

    while (true) {
        BigInteger p = generatePrime(bitLength, generator, *primalityTest, minimumProbability);
        BigInteger q = generatePrime(bitLength, generator, *primalityTest, minimumProbability);
        if (p == q) continue;

        BigInteger n = p * q;
        BigInteger phi = (p - 1) * (q - 1);

        for (BigInteger d = 3; ; d += 2) {
            BigInteger threeD = 3 * d;
            if (threeD * threeD * threeD * threeD >= n) break;
            if (NumberTheoryService::gcd(d, phi) != 1) continue;

            BezoutResult result = NumberTheoryService::extendedGcd(d, phi);
            BigInteger e = result.x % phi;
            if (e < 0) e += phi;
            if (e <= d || e <= 1) continue;

            return RSAKeyPair{n, e, d};
        }
    }
}