find_package(GTest CONFIG QUIET)
if(NOT GTest_FOUND AND EXISTS /usr/src/googletest/CMakeLists.txt)
        add_subdirectory(/usr/src/googletest googletest-build)
elseif(NOT GTest_FOUND)
        message(FATAL_ERROR "GoogleTest sources were not found. Install the googletest package or provide a project-local GoogleTest source.")
endif()

add_executable(tests1
        bits_tests.cpp
        context_tests.cpp
        des_tests.cpp
        deal_tests.cpp
        feistel_tests.cpp
        modes_tests.cpp
        padding_tests.cpp
        regression_tests.cpp
)

target_compile_features(tests1
        PRIVATE
            cxx_std_23
)

target_link_libraries(tests1
        PRIVATE
        lib1
            GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(tests1)
