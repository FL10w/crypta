#include "../include/algorithms/EuclideanGcd.h"
#include "../include/algorithms/ExtendedEuclideanGcd.h"
#include "../include/algorithms/JacobiSymbol.h"
#include "../include/algorithms/LegendreSymbol.h"
#include "../include/laba2.h"
#include "../include/algorithms/BinaryEuclideanGcd.h"
#include "../include/algorithms/ModularExponentiation.h"
#include "../include/algorithms/EulerFunction.h"
#include "../include/algorithms/CarmichaelFunction.h"
#include "../include/NumberTheoryService.h"
#include "../include/primality/FermatPrimalityTest.h"
#include "../include/primality/SolovayStrassenPrimalityTest.h"
#include "../include/primality/MillerRabinPrimalityTest.h"
#include "../include/rsa/RSAService.h"
#include "../include/rsa/WienerAttackService.h"
#include "../include/rsa/VulnerableRSAKeyGenerator.h"
#include "../include/rsa/VulnerableRSAKeyGenerator.h"

#include <iostream>
#include <string>
#include <limits>

int passed = 0;
int failed = 0;

void check(const std::string& name, bool result) {
    if (result) {
        std::cout << "[PASS] " << name << '\n';
        ++passed;
    }
    else {
        std::cout << "[FAIL] " << name << '\n';
        ++failed;
    }
}

template <typename Function>
void checkThrows(const std::string& name, Function function) {
    try {
        function();
        check(name, false);
    }
    catch (Error error) {
        check(name, true);
    }
    catch (...) {
        check(name, false);
    }
}

void testEuclideanGcd() {
    check("GCD (48, 18)", EuclideanGcd::calculate(48, 18) == 6);
    check("GCD (17, 5)", EuclideanGcd::calculate(17, 5) == 1);
    check("GCD (-24, 18)", EuclideanGcd::calculate(-24, 18) == 6);
    check("GCD (0, 7)", EuclideanGcd::calculate(0, 7) == 7);
    check("GCD (0, 0)", EuclideanGcd::calculate(0, 0) == 0);
    check("GCD (48, -18)", EuclideanGcd::calculate(48, -18) == 6);
    check("GCD (-48, -18)", EuclideanGcd::calculate(-48, -18) == 6);

    BigInteger a("123456789012345678901234567890");
    BigInteger b("987654321098765432109876543210");

    check("GCD BigInteger", EuclideanGcd::calculate(a, b) ==
        BigInteger("9000000000900000000090"));

    check("GCD BigInteger negative", EuclideanGcd::calculate(-a, b) ==
        BigInteger("9000000000900000000090"));
}

void testExtendedEuclideanGcd() {
    BezoutResult result;

    result = ExtendedEuclideanGcd::calculate(30, 18);
    check("Extended GCD (30, 18)", result.gcd == 6);
    check("Bezout identity (30, 18)",
        30 * result.x + 18 * result.y == result.gcd);

    result = ExtendedEuclideanGcd::calculate(17, 5);
    check("Extended GCD coprime", result.gcd == 1);
    check("Bezout identity coprime",
        17 * result.x + 5 * result.y == result.gcd);

    result = ExtendedEuclideanGcd::calculate(48, 18);
    check("Extended GCD (48, 18)", result.gcd == 6);
    check("Bezout identity (48, 18)",
        48 * result.x + 18 * result.y == result.gcd);

    result = ExtendedEuclideanGcd::calculate(-30, 18);
    check("Extended GCD negative a", result.gcd == 6);
    check("Bezout identity negative a",
        -30 * result.x + 18 * result.y == result.gcd);

    result = ExtendedEuclideanGcd::calculate(30, -18);
    check("Extended GCD negative b", result.gcd == 6);
    check("Bezout identity negative b",
        30 * result.x - 18 * result.y == result.gcd);

    result = ExtendedEuclideanGcd::calculate(-30, -18);
    check("Extended GCD both negative", result.gcd == 6);
    check("Bezout identity both negative",
        -30 * result.x - 18 * result.y == result.gcd);

    result = ExtendedEuclideanGcd::calculate(0, 7);
    check("Extended GCD (0, 7)", result.gcd == 7);
    check("Bezout identity (0, 7)",
        result.x * 0 + result.y * 7 == result.gcd);

    result = ExtendedEuclideanGcd::calculate(7, 0);
    check("Extended GCD (7, 0)", result.gcd == 7);
    check("Bezout identity (7, 0)",
        result.x * 7 + result.y * 0 == result.gcd);

    result = ExtendedEuclideanGcd::calculate(0, -7);
    check("Extended GCD (0, -7)", result.gcd == 7);
    check("Bezout identity (0, -7)",
        result.x * 0 - result.y * 7 == result.gcd);

    result = ExtendedEuclideanGcd::calculate(0, 0);
    check("Extended GCD (0, 0)", result.gcd == 0);
    check("Bezout identity (0, 0)",
        result.x * 0 + result.y * 0 == result.gcd);

    result = ExtendedEuclideanGcd::calculate(12, 12);
    check("Extended GCD equal numbers", result.gcd == 12);
    check("Bezout identity equal numbers",
        12 * result.x + 12 * result.y == result.gcd);

    result = ExtendedEuclideanGcd::calculate(1, 1);
    check("Extended GCD (1, 1)", result.gcd == 1);
    check("Bezout identity (1, 1)",
        result.x + result.y == result.gcd);

    BigInteger a("12345678901234567890");
    BigInteger b("123456789012345678900");

    result = ExtendedEuclideanGcd::calculate(a, b);
    check("Extended GCD BigInteger", result.gcd == a);
    check("Bezout identity BigInteger",
        a * result.x + b * result.y == result.gcd);

    result = ExtendedEuclideanGcd::calculate(-a, b);
    check("Extended GCD BigInteger negative", result.gcd == a);
    check("Bezout identity BigInteger negative",
        -a * result.x + b * result.y == result.gcd);

    check("Extended GCD nonnegative result",
        result.gcd >= 0);
}

void testJacobiSymbol() {
    check("Jacobi (3, 7)", JacobiSymbol::calculate(3, 7) == -1);
    check("Jacobi (2, 7)", JacobiSymbol::calculate(2, 7) == 1);
    check("Jacobi (0, 7)", JacobiSymbol::calculate(0, 7) == 0);
    check("Jacobi (7, 9)", JacobiSymbol::calculate(7, 9) == 1);
    check("Jacobi (2, 9)", JacobiSymbol::calculate(2, 9) == 1);
    check("Jacobi (-1, 7)", JacobiSymbol::calculate(-1, 7) == -1);

    checkThrows("Jacobi even denominator", [] {
        JacobiSymbol::calculate(3, 8);
    });

    checkThrows("Jacobi denominator equals 1", [] {
        JacobiSymbol::calculate(3, 1);
    });

    checkThrows("Jacobi zero denominator", [] {
        JacobiSymbol::calculate(3, 0);
    });

    BigInteger a("123456789012345678901234567890");
    BigInteger n("987654321098765432109876543211");

    int result = JacobiSymbol::calculate(a, n);
    check("Jacobi BigInteger result range", result >= -1 && result <= 1);
}

void testLegendreSymbol() {
    check("Legendre (3, 7)", LegendreSymbol::calculate(3, 7) == -1);
    check("Legendre (2, 7)", LegendreSymbol::calculate(2, 7) == 1);
    check("Legendre (0, 7)", LegendreSymbol::calculate(0, 7) == 0);
    check("Legendre (7, 7)", LegendreSymbol::calculate(7, 7) == 0);
    check("Legendre (-1, 7)", LegendreSymbol::calculate(-1, 7) == -1);

    checkThrows("Legendre composite denominator", [] {
        LegendreSymbol::calculate(2, 9);
    });

    checkThrows("Legendre even denominator", [] {
        LegendreSymbol::calculate(2, 8);
    });

    checkThrows("Legendre denominator equals 2", [] {
        LegendreSymbol::calculate(1, 2);
    });

    BigInteger a("12345678901234567890");

    int result = LegendreSymbol::calculate(a, 7);
    check("Legendre BigInteger result range", result >= -1 && result <= 1);
}

void testBinaryEuclideanGcd() {
    check("Binary GCD: gcd(48, 18) = 6",
        BinaryEuclideanGcd::calculate(48, 18) == 6);

    check("Binary GCD: gcd(7, 3) = 1",
        BinaryEuclideanGcd::calculate(7, 3) == 1);

    check("Binary GCD: gcd(0, 15) = 15",
        BinaryEuclideanGcd::calculate(0, 15) == 15);

    check("Binary GCD: gcd(15, 0) = 15",
        BinaryEuclideanGcd::calculate(15, 0) == 15);

    check("Binary GCD: gcd(0, 0) = 0",
        BinaryEuclideanGcd::calculate(0, 0) == 0);

    check("Binary GCD: negative a",
        BinaryEuclideanGcd::calculate(-48, 18) == 6);

    check("Binary GCD: negative b",
        BinaryEuclideanGcd::calculate(48, -18) == 6);

    check("Binary GCD: both negative",
        BinaryEuclideanGcd::calculate(-48, -18) == 6);

    check("Binary GCD: equal numbers",
        BinaryEuclideanGcd::calculate(17, 17) == 17);

    check("Binary GCD: powers of two",
        BinaryEuclideanGcd::calculate(256, 64) == 64);

    check("Binary GCD: coprime numbers",
        BinaryEuclideanGcd::calculate(35, 64) == 1);

    BigInteger a = BigInteger("12345678901234567890");
    BigInteger b = BigInteger("9876543210");

    check("Binary GCD: BigInteger",
        BinaryEuclideanGcd::calculate(a, b) ==
        EuclideanGcd::calculate(a, b));

    check("Binary GCD: compare with Euclidean GCD",
        BinaryEuclideanGcd::calculate(462, 1071) ==
        EuclideanGcd::calculate(462, 1071));
}

void testModularExponentiation() {
    check("Modular exponentiation: 3^4 mod 5 = 1",
        ModularExponentiation::calculate(3, 4, 5) == 1);

    check("Modular exponentiation: 3^13 mod 7 = 3",
        ModularExponentiation::calculate(3, 13, 7) == 3);

    check("Modular exponentiation: 2^10 mod 1000 = 24",
        ModularExponentiation::calculate(2, 10, 1000) == 24);

    check("Modular exponentiation: exponent zero",
        ModularExponentiation::calculate(5, 0, 7) == 1);

    check("Modular exponentiation: 0^0 mod 7 = 1",
        ModularExponentiation::calculate(0, 0, 7) == 1);

    check("Modular exponentiation: base zero",
        ModularExponentiation::calculate(0, 5, 7) == 0);

    check("Modular exponentiation: base one",
        ModularExponentiation::calculate(1, 100, 7) == 1);

    check("Modular exponentiation: exponent one",
        ModularExponentiation::calculate(12, 1, 7) == 5);

    check("Modular exponentiation: base greater than modulus",
        ModularExponentiation::calculate(17, 3, 5) == 3);

    check("Modular exponentiation: modulus one",
        ModularExponentiation::calculate(123, 456, 1) == 0);

    check("Modular exponentiation: negative base",
        ModularExponentiation::calculate(-2, 3, 5) == 2);

    check("Modular exponentiation: negative base even exponent",
        ModularExponentiation::calculate(-2, 4, 5) == 1);

    check("Modular exponentiation: negative base divisible by modulus",
        ModularExponentiation::calculate(-15, 3, 5) == 0);

    check("Modular exponentiation: large exponent",
        ModularExponentiation::calculate(2, 100, 1009) == 164);

    BigInteger base = BigInteger("12345678901234567890");
    BigInteger exponent = BigInteger("12345");
    BigInteger modulus = BigInteger("987654321");

    check("Modular exponentiation: BigInteger arguments",
        ModularExponentiation::calculate(base, exponent, modulus) >= 0 &&
        ModularExponentiation::calculate(base, exponent, modulus) < modulus);

    check("Modular exponentiation: negative exponent",
    ModularExponentiation::calculate(2, -3, 5) == 2);

    check("Modular exponentiation: negative base and exponent",
        ModularExponentiation::calculate(-2, -1, 5) == 2);

    checkThrows("Modular exponentiation: negative exponent without inverse",
        [] { ModularExponentiation::calculate(2, -1, 4); });

    check("Modular exponentiation: negative exponent with modulus one",
        ModularExponentiation::calculate(0, -1, 1) == 0);

    checkThrows("Modular exponentiation: zero modulus",
        [] { ModularExponentiation::calculate(2, 3, 0); });

    checkThrows("Modular exponentiation: negative modulus",
        [] { ModularExponentiation::calculate(2, 3, -5); });
}

void testEulerFunction() {
    // Метод по определению

    check("Euler definition: phi(1) = 1",
        EulerFunction::byDefinition(1) == 1);

    check("Euler definition: phi(2) = 1",
        EulerFunction::byDefinition(2) == 1);

    check("Euler definition: phi(7) = 6",
        EulerFunction::byDefinition(7) == 6);

    check("Euler definition: phi(12) = 4",
        EulerFunction::byDefinition(12) == 4);

    check("Euler definition: phi(16) = 8",
        EulerFunction::byDefinition(16) == 8);

    check("Euler definition: phi(27) = 18",
        EulerFunction::byDefinition(27) == 18);

    check("Euler definition: phi(36) = 12",
        EulerFunction::byDefinition(36) == 12);

    check("Euler definition: phi(100) = 40",
        EulerFunction::byDefinition(100) == 40);

    checkThrows("Euler definition: n = 0",
        [] { EulerFunction::byDefinition(0); });

    checkThrows("Euler definition: negative n",
        [] { EulerFunction::byDefinition(-5); });


    // Метод разложения на простые множители

    check("Euler factorization: phi(1) = 1",
        EulerFunction::byPrimeFactorization(1) == 1);

    check("Euler factorization: phi(2) = 1",
        EulerFunction::byPrimeFactorization(2) == 1);

    check("Euler factorization: phi(13) = 12",
        EulerFunction::byPrimeFactorization(13) == 12);

    check("Euler factorization: phi(16) = 8",
        EulerFunction::byPrimeFactorization(16) == 8);

    check("Euler factorization: phi(27) = 18",
        EulerFunction::byPrimeFactorization(27) == 18);

    check("Euler factorization: phi(36) = 12",
        EulerFunction::byPrimeFactorization(36) == 12);

    check("Euler factorization: phi(100) = 40",
        EulerFunction::byPrimeFactorization(100) == 40);

    check("Euler factorization: phi(97) = 96",
        EulerFunction::byPrimeFactorization(97) == 96);

    checkThrows("Euler factorization: n = 0",
        [] { EulerFunction::byPrimeFactorization(0); });

    checkThrows("Euler factorization: negative n",
        [] { EulerFunction::byPrimeFactorization(-5); });


    // Метод через формулу Фурье

    check("Euler Fourier: phi(1) = 1",
        EulerFunction::byFourierTransform(1) == 1);

    check("Euler Fourier: phi(2) = 1",
        EulerFunction::byFourierTransform(2) == 1);

    check("Euler Fourier: phi(3) = 2",
        EulerFunction::byFourierTransform(3) == 2);

    check("Euler Fourier: phi(12) = 4",
        EulerFunction::byFourierTransform(12) == 4);

    check("Euler Fourier: phi(16) = 8",
        EulerFunction::byFourierTransform(16) == 8);

    check("Euler Fourier: phi(27) = 18",
        EulerFunction::byFourierTransform(27) == 18);

    check("Euler Fourier: phi(36) = 12",
        EulerFunction::byFourierTransform(36) == 12);

    checkThrows("Euler Fourier: n = 0",
        [] { EulerFunction::byFourierTransform(0); });

    checkThrows("Euler Fourier: negative n",
        [] { EulerFunction::byFourierTransform(-5); });


    // Сравнение всех трёх методов на небольших n

    bool allEqual = true;

    for (int n = 1; n <= 40; ++n) {
        BigInteger byDefinition =
            EulerFunction::byDefinition(n);

        BigInteger byFactorization =
            EulerFunction::byPrimeFactorization(n);

        BigInteger byFourier =
            EulerFunction::byFourierTransform(n);

        if (byDefinition != byFactorization ||
            byDefinition != byFourier) {
            allEqual = false;
            break;
        }
    }

    check("Euler: all methods agree for n = 1..40",
        allEqual);
}

void testCarmichaelFunction() {
    std::cout << "\n--- Carmichael Function Tests ---\n";

    // Граничные значения
    check("Carmichael(1) = 1",
          CarmichaelFunction::calculate(1) == 1);
    check("Carmichael(2) = 1",
          CarmichaelFunction::calculate(2) == 1);

    // Некорректные аргументы
    checkThrows("Carmichael(0) throws",
                []() { CarmichaelFunction::calculate(0); });
    checkThrows("Carmichael(-1) throws",
                []() { CarmichaelFunction::calculate(-1); });
    checkThrows("Carmichael(-100) throws",
                []() { CarmichaelFunction::calculate(-100); });

    // Степени двойки
    check("Carmichael(4) = 2",
          CarmichaelFunction::calculate(4) == 2);
    check("Carmichael(8) = 2",
          CarmichaelFunction::calculate(8) == 2);
    check("Carmichael(16) = 4",
          CarmichaelFunction::calculate(16) == 4);
    check("Carmichael(32) = 8",
          CarmichaelFunction::calculate(32) == 8);
    check("Carmichael(64) = 16",
          CarmichaelFunction::calculate(64) == 16);

    // Нечётные простые числа
    check("Carmichael(3) = 2",
          CarmichaelFunction::calculate(3) == 2);
    check("Carmichael(5) = 4",
          CarmichaelFunction::calculate(5) == 4);
    check("Carmichael(7) = 6",
          CarmichaelFunction::calculate(7) == 6);
    check("Carmichael(13) = 12",
          CarmichaelFunction::calculate(13) == 12);
    check("Carmichael(97) = 96",
          CarmichaelFunction::calculate(97) == 96);

    // Степени нечётных простых чисел
    check("Carmichael(9) = 6",
          CarmichaelFunction::calculate(9) == 6);
    check("Carmichael(27) = 18",
          CarmichaelFunction::calculate(27) == 18);
    check("Carmichael(25) = 20",
          CarmichaelFunction::calculate(25) == 20);
    check("Carmichael(125) = 100",
          CarmichaelFunction::calculate(125) == 100);

    // Составные числа с разными простыми множителями
    check("Carmichael(6) = 2",
          CarmichaelFunction::calculate(6) == 2);
    check("Carmichael(10) = 4",
          CarmichaelFunction::calculate(10) == 4);
    check("Carmichael(12) = 2",
          CarmichaelFunction::calculate(12) == 2);
    check("Carmichael(15) = 4",
          CarmichaelFunction::calculate(15) == 4);
    check("Carmichael(21) = 6",
          CarmichaelFunction::calculate(21) == 6);
    check("Carmichael(30) = 4",
          CarmichaelFunction::calculate(30) == 4);
    check("Carmichael(45) = 12",
          CarmichaelFunction::calculate(45) == 12);
    check("Carmichael(60) = 4",
          CarmichaelFunction::calculate(60) == 4);
    check("Carmichael(100) = 20",
          CarmichaelFunction::calculate(100) == 20);

    // Проверка оставшегося простого множителя после цикла
    check("Carmichael(14) = 6",
          CarmichaelFunction::calculate(14) == 6);
    check("Carmichael(35) = 12",
          CarmichaelFunction::calculate(35) == 12);
    check("Carmichael(77) = 30",
          CarmichaelFunction::calculate(77) == 30);

    // Проверка большого простого числа
    check("Carmichael(1000003) = 1000002",
          CarmichaelFunction::calculate(BigInteger(1000003)) == 1000002);
}

void testNumberTheoryService() {
    std::cout << "\n--- Number Theory Service Tests ---\n";

    // Символ Лежандра
    check("Service: Legendre symbol",
        NumberTheoryService::legendreSymbol(3, 7) == -1);

    // Символ Якоби
    check("Service: Jacobi symbol",
        NumberTheoryService::jacobiSymbol(3, 7) == -1);

    // Алгоритм Евклида
    check("Service: Euclidean GCD",
        NumberTheoryService::gcd(48, 18) == 6);

    // Расширенный алгоритм Евклида и соотношение Безу
    BezoutResult result =
        NumberTheoryService::extendedGcd(30, 18);

    check("Service: Extended GCD",
        result.gcd == 6);

    check("Service: Bezout identity",
        30 * result.x + 18 * result.y == result.gcd);

    // Бинарный алгоритм Евклида
    check("Service: Binary GCD",
        NumberTheoryService::binaryGcd(48, 18) == 6);

    // Возведение в степень по модулю
    check("Service: Modular exponentiation",
        NumberTheoryService::modularExponentiation(2, 10, 1000) == 24);

    // Функция Эйлера: три способа
    check("Service: Euler by definition",
        NumberTheoryService::eulerByDefinition(12) == 4);

    check("Service: Euler by prime factorization",
        NumberTheoryService::eulerByPrimeFactorization(12) == 4);

    check("Service: Euler by Fourier transform",
        NumberTheoryService::eulerByFourierTransform(12) == 4);

    // Функция Кармайкла
    check("Service: Carmichael function",
        NumberTheoryService::carmichael(12) == 2);

    // Проверка обработки некорректных аргументов
    checkThrows("Service: invalid Jacobi denominator",
        [] {
            NumberTheoryService::jacobiSymbol(3, 8);
        });

    checkThrows("Service: invalid Euler argument",
        [] {
            NumberTheoryService::eulerByDefinition(0);
        });

    checkThrows("Service: invalid Carmichael argument",
        [] {
            NumberTheoryService::carmichael(0);
        });
}


void testOnePrimalityAlgorithm(const std::string& algorithmName, IProbabilisticPrimalityTest& test) {
    const double probability = 0.999999;

    // Простые числа
    check(algorithmName + ": prime 2", test.IsProbablyPrime(2, probability));
    check(algorithmName + ": prime 3", test.IsProbablyPrime(3, probability));
    check(algorithmName + ": prime 5", test.IsProbablyPrime(5, probability));
    check(algorithmName + ": prime 97", test.IsProbablyPrime(97, probability));
    check(algorithmName + ": large prime 104729", test.IsProbablyPrime(104729, probability));

    // Числа меньше двух
    check(algorithmName + ": negative number", !test.IsProbablyPrime(-7, probability));
    check(algorithmName + ": zero", !test.IsProbablyPrime(0, probability));
    check(algorithmName + ": one", !test.IsProbablyPrime(1, probability));

    // Чётные составные числа
    check(algorithmName + ": even composite 4", !test.IsProbablyPrime(4, probability));
    check(algorithmName + ": even composite 100", !test.IsProbablyPrime(100, probability));

    // Нечётные составные числа
    check(algorithmName + ": odd composite 9", !test.IsProbablyPrime(9, probability));
    check(algorithmName + ": odd composite 15", !test.IsProbablyPrime(15, probability));
    check(algorithmName + ": odd composite 25", !test.IsProbablyPrime(25, probability));
    check(algorithmName + ": odd composite 49", !test.IsProbablyPrime(49, probability));
    check(algorithmName + ": odd composite 65", !test.IsProbablyPrime(65, probability));

    // Граничное допустимое значение вероятности
    check(algorithmName + ": minimum probability 0.5", test.IsProbablyPrime(97, 0.5));

    // Недопустимые значения вероятности
    checkThrows(algorithmName + ": probability below 0.5 throws", [&test] {
        test.IsProbablyPrime(97, 0.49);
    });

    checkThrows(algorithmName + ": probability 1.0 throws", [&test] {
        test.IsProbablyPrime(97, 1.0);
    });

    checkThrows(algorithmName + ": probability above 1.0 throws", [&test] {
        test.IsProbablyPrime(97, 1.1);
    });

    checkThrows(algorithmName + ": negative probability throws", [&test] {
        test.IsProbablyPrime(97, -1.0);
    });

    checkThrows(algorithmName + ": NaN probability throws", [&test] {
        test.IsProbablyPrime(97, std::numeric_limits<double>::quiet_NaN());
    });

    checkThrows(algorithmName + ": infinite probability throws", [&test] {
        test.IsProbablyPrime(97, std::numeric_limits<double>::infinity());
    });
}

void testProbabilisticPrimalityTests() {
    std::cout << "\n--- Probabilistic Primality Tests ---\n";

    FermatPrimalityTest fermat;
    SolovayStrassenPrimalityTest solovayStrassen;
    MillerRabinPrimalityTest millerRabin;

    testOnePrimalityAlgorithm("Fermat", fermat);
    testOnePrimalityAlgorithm("Solovay-Strassen", solovayStrassen);
    testOnePrimalityAlgorithm("Miller-Rabin", millerRabin);

    // Диагностика ограничения теста Ферма на числе Кармайкла 561.
    int fermatAccepted561 = 0;

    for (int i = 0; i < 20; ++i) {
        if (fermat.IsProbablyPrime(561, 0.5)) {
            ++fermatAccepted561;
        }
    }

    std::cout << "[INFO] Fermat accepted 561 in "
              << fermatAccepted561
              << "/20 runs (diagnostic only)\n";
}

void testRSAService() {
    std::cout << "\n--- RSA Service Tests ---\n";
    using TestType = RSAService::PrimalityTestType;

    auto checkConstructs = [](const std::string& name, auto function) {
        try {
            function();
            check(name, true);
        }
        catch (...) {
            check(name, false);
        }
    };

    // 1. Проверка конструкторов со всеми тестами простоты
    checkConstructs("RSA: constructor with Fermat", [] {
        RSAService rsa(TestType::Fermat, 0.999, 32);
    });

    checkConstructs("RSA: constructor with Solovay-Strassen", [] {
        RSAService rsa(TestType::SolovayStrassen, 0.999, 32);
    });

    checkConstructs("RSA: constructor with Miller-Rabin", [] {
        RSAService rsa(TestType::MillerRabin, 0.999, 32);
    });

    // 2. Проверка допустимой и недопустимой вероятности
    checkConstructs("RSA: probability 0.5 is accepted", [] {
        RSAService rsa(TestType::MillerRabin, 0.5, 32);
    });

    checkThrows("RSA: probability below 0.5 throws", [] {
        RSAService rsa(TestType::MillerRabin, 0.49, 32);
    });

    checkThrows("RSA: probability 1.0 throws", [] {
        RSAService rsa(TestType::MillerRabin, 1.0, 32);
    });

    checkThrows("RSA: probability above 1.0 throws", [] {
        RSAService rsa(TestType::MillerRabin, 1.1, 32);
    });

    // 3. Проверка битовой длины
    checkConstructs("RSA: bit length 16 is accepted", [] {
        RSAService rsa(TestType::MillerRabin, 0.999, 16);
    });

    checkThrows("RSA: bit length below 16 throws", [] {
        RSAService rsa(TestType::MillerRabin, 0.999, 15);
    });

    // 4. Проверка недопустимого типа теста
    checkThrows("RSA: invalid test type throws", [] {
        RSAService rsa(static_cast<TestType>(-1), 0.999, 32);
    });

    // 5. Генерация ключей
    RSAService rsa(TestType::MillerRabin, 0.999, 32);
    RSAKeyPair keyPair = rsa.generateKeyPair();

    check("RSA: modulus is positive", keyPair.n > 0);
    check("RSA: public exponent is 65537", keyPair.e == 65537);
    check("RSA: private exponent is positive", keyPair.d > 0);
    check("RSA: private exponent is less than modulus",
        keyPair.d < keyPair.n);

    // 6. Шифрование и дешифрование граничных значений
    check("RSA: encrypt zero", rsa.encrypt(0, keyPair) == 0);
    check("RSA: decrypt zero", rsa.decrypt(0, keyPair) == 0);
    check("RSA: encrypt one", rsa.encrypt(1, keyPair) == 1);
    check("RSA: decrypt one", rsa.decrypt(1, keyPair) == 1);

    // 7. Проверка разных сообщений
    BigInteger messages[] = {2, 42, 12345, 65536, 1000000};
    bool allRestored = true;

    for (const BigInteger& message : messages) {
        if (message >= keyPair.n) {
            allRestored = false;
            break;
        }

        BigInteger ciphertext = rsa.encrypt(message, keyPair);
        BigInteger decrypted = rsa.decrypt(ciphertext, keyPair);

        if (decrypted != message) {
            allRestored = false;
            break;
        }
    }

    check("RSA: all messages restored", allRestored);

    // 8. Максимальное допустимое сообщение
    BigInteger maxMessage = keyPair.n - 1;
    BigInteger maxCiphertext = rsa.encrypt(maxMessage, keyPair);

    check("RSA: ciphertext is in valid range",
        maxCiphertext >= 0 && maxCiphertext < keyPair.n);
    check("RSA: decrypt n - 1",
        rsa.decrypt(maxCiphertext, keyPair) == maxMessage);

    // 9. Проверка некорректных сообщений
    checkThrows("RSA: negative message throws", [&] {
        rsa.encrypt(-1, keyPair);
    });

    checkThrows("RSA: message equal to n throws", [&] {
        rsa.encrypt(keyPair.n, keyPair);
    });

    checkThrows("RSA: message greater than n throws", [&] {
        rsa.encrypt(keyPair.n + 1, keyPair);
    });

    checkThrows("RSA: negative ciphertext throws", [&] {
        rsa.decrypt(-1, keyPair);
    });

    checkThrows("RSA: ciphertext equal to n throws", [&] {
        rsa.decrypt(keyPair.n, keyPair);
    });

    checkThrows("RSA: ciphertext greater than n throws", [&] {
        rsa.decrypt(keyPair.n + 1, keyPair);
    });

    // 10. Повторная генерация ключей
    RSAKeyPair secondKeyPair = rsa.generateKeyPair();

    check("RSA: second key pair has positive modulus",
        secondKeyPair.n > 0);
    check("RSA: second key pair has public exponent 65537",
        secondKeyPair.e == 65537);

    BigInteger secondMessage = 54321;
    BigInteger secondCiphertext =
        rsa.encrypt(secondMessage, secondKeyPair);

    check("RSA: second key pair encrypts and decrypts",
        rsa.decrypt(secondCiphertext, secondKeyPair) == secondMessage);
}

void testWienerAttackService() {
    std::cout << "\n--- Wiener Attack Tests ---\n";

    // Известная уязвимая RSA-пара: p = 53, q = 59, d = 3
    // n = 3127, phi(n) = 3016, e = 2011
    WienerAttackResult result = WienerAttackService::attack(3127, 2011);

    check("Wiener: attack succeeds", result.success);
    check("Wiener: private exponent recovered", result.privateExponent == 3);
    check("Wiener: Euler function recovered", result.eulerFunction == 3016);
    check("Wiener: convergents are collected", !result.convergents.empty());

    checkThrows("Wiener: zero modulus throws", [] {
        WienerAttackService::attack(0, 3);
    });

    checkThrows("Wiener: negative modulus throws", [] {
        WienerAttackService::attack(-15, 7);
    });

    checkThrows("Wiener: zero public exponent throws", [] {
        WienerAttackService::attack(15, 0);
    });

    // 3. Проверка генератора уязвимых ключей
    WienerVulnerableKeyGenerator generator(RSAService::PrimalityTestType::MillerRabin, 0.999999);

    for (int i = 1; i <= 5; ++i) {
        RSAKeyPair keyPair = generator.generate(16);
        WienerAttackResult attackResult =
            WienerAttackService::attack(keyPair.n, keyPair.e);

        std::string testName = "Wiener generated key " + std::to_string(i);

        check(testName + ": attack succeeds", attackResult.success);

        if (attackResult.success) {
            check(testName + ": private exponent recovered",
                attackResult.privateExponent == keyPair.d);

            check(testName + ": Euler function recovered",
                keyPair.e * keyPair.d % attackResult.eulerFunction == 1);
        }
    }
}


int main() {
    testEuclideanGcd();
    testExtendedEuclideanGcd();
    testJacobiSymbol();
    testLegendreSymbol();
    testBinaryEuclideanGcd();
    testModularExponentiation();
    testEulerFunction();
    testCarmichaelFunction();

    testNumberTheoryService();
    testProbabilisticPrimalityTests();
    testRSAService();
    testWienerAttackService();

    std::cout << "\nPassed: " << passed << '\n';
    std::cout << "Failed: " << failed << '\n';

    return failed == 0 ? 0 : 1;
}
