#pragma once

#include "../laba2.h"

struct RSAKeyPair {
    BigInteger n;
    BigInteger e;
    BigInteger d;
};