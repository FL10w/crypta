#pragma once

#include "RSAKeyPair.h"
#include "RSAService.h"
#include <memory>

class WienerVulnerableKeyGenerator {
public:
    WienerVulnerableKeyGenerator(RSAService::PrimalityTestType testType, double minimumProbability);
    RSAKeyPair generate(unsigned int bitLength);

private:
    RSAService::PrimalityTestType testType;
    double minimumProbability;
    std::unique_ptr<IProbabilisticPrimalityTest> primalityTest;
};