#pragma once

#include "ProbabilisticPrimalityTestBase.h"

class MillerRabinPrimalityTest : public ProbabilisticPrimalityTestBase {
protected:
    bool TestOneRound(const BigInteger& n, const BigInteger& a) override;
    int CalculateIterationCount(double minimumProbability) override;
};