#pragma once

#include "../laba2.h"

#include <vector>

struct WienerConvergent {
    BigInteger numerator;
    BigInteger denominator;
};

struct WienerAttackResult {
    bool success = false;
    BigInteger privateExponent = 0; //d
    BigInteger eulerFunction = 0;
    std::vector<WienerConvergent> convergents;  // все дроби, даже не подходящие
};

class WienerAttackService {
public:
    static WienerAttackResult attack(
        const BigInteger& n,
        const BigInteger& e
    );
};