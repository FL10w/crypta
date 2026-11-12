#!/usr/bin/env bash
# Linux launcher; the laboratory implementation and tests stay unchanged.
set -euo pipefail

lab_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$lab_dir"
mkdir -p build

# Original includes use "rsa"; the actual directory is named "RSA".
if [[ ! -e include/rsa ]]; then
    ln -s RSA include/rsa
fi

boost_flags=()
if [[ -n "${BOOST_INCLUDE_DIR:-}" ]]; then
    if [[ ! -f "$BOOST_INCLUDE_DIR/boost/multiprecision/cpp_int.hpp" ]]; then
        echo "BOOST_INCLUDE_DIR must contain boost/multiprecision/cpp_int.hpp" >&2
        exit 1
    fi
    boost_flags=(-isystem "$BOOST_INCLUDE_DIR")
elif [[ -f build/deps/usr/include/boost/multiprecision/cpp_int.hpp ]]; then
    boost_flags=(-isystem "$lab_dir/build/deps/usr/include")
elif [[ ! -f /usr/include/boost/multiprecision/cpp_int.hpp && ! -f /usr/local/include/boost/multiprecision/cpp_int.hpp ]]; then
    echo "Boost.Multiprecision headers are missing. See ../lab2_demo.txt." >&2
    exit 1
fi

sources=(src/*.cpp src/algorithms/*.cpp src/primality/*.cpp src/RSA/*.cpp)
"${CXX:-g++}" -std=c++20 -O2 -Wall -Wextra -Wpedantic \
    "${boost_flags[@]}" "${sources[@]}" tests/test_laba2.cpp \
    -o build/test_laba2

exec ./build/test_laba2
