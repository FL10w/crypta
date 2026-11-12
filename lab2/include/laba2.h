#pragma once
#include <boost/multiprecision/cpp_int.hpp>

using BigInteger = boost::multiprecision::cpp_int;


enum struct Error {
    ERROR_INVALID_ARGUMENT,
    ERROR_INVALID_PRIME,
};

bool isPrime(BigInteger p);