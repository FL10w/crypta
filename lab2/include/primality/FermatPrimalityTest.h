#pragma once

#include "ProbabilisticPrimalityTestBase.h"

class FermatPrimalityTest : public ProbabilisticPrimalityTestBase {
protected:
    bool TestOneRound(const BigInteger& n, const BigInteger& a) override;

    int CalculateIterationCount(double minimumProbability) override;
};