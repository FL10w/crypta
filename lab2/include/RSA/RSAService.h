#pragma once

#include "RSAKeyPair.h"
#include "../primality/IProbabilisticPrimalityTest.h"
#include <memory>

class RSAService {
public:
    enum class PrimalityTestType {
        Fermat,
        SolovayStrassen,
        MillerRabin
    };

    class KeyGenerator {
    public:
        KeyGenerator(PrimalityTestType testType, double minimumProbability, unsigned int bitLength);

        RSAKeyPair generateKeyPair();

    private:
        PrimalityTestType testType;
        double minimumProbability;
        unsigned int bitLength;

        std::unique_ptr<IProbabilisticPrimalityTest> primalityTest;
    };

    RSAService(
        PrimalityTestType testType, double minimumProbability, unsigned int bitLength);

    RSAKeyPair generateKeyPair();

    BigInteger encrypt(const BigInteger& message, const RSAKeyPair& keyPair) const;

    BigInteger decrypt(const BigInteger& ciphertext, const RSAKeyPair& keyPair) const;

private:
    KeyGenerator keyGenerator;
};