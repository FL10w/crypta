#pragma once

#include "IProbabilisticPrimalityTest.h"

class ProbabilisticPrimalityTestBase
    : public IProbabilisticPrimalityTest {
public:
    bool IsProbablyPrime(const BigInteger& value, double minimumProbability) override;  // общий метод

protected:
    virtual bool TestOneRound(const BigInteger& n, const BigInteger& a) = 0;    // наследники реализуют. вриртуальный

    virtual int CalculateIterationCount(double minimumProbability) = 0;
};