cmake_minimum_required(VERSION 3.28)

project(CryptographyLab1 LANGUAGES CXX)

if(NOT CMAKE_GENERATOR MATCHES "^Ninja")
    message(FATAL_ERROR "C++ modules require Ninja. Configure with: cmake -S . -B build -G Ninja")
endif()
if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_VERSION VERSION_LESS 15)
    message(FATAL_ERROR "This project requires GCC 15+ with the libstdc++ std module")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

# Build libstdc++'s std module as an ordinary module target. This also works
# with CMake 3.28+, without experimental import-std gates or compiler wrappers.
execute_process(
    COMMAND "${CMAKE_CXX_COMPILER}" -print-file-name=libstdc++.modules.json
    OUTPUT_VARIABLE std_metadata
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY)
if(NOT EXISTS "${std_metadata}")
    message(FATAL_ERROR "libstdc++.modules.json is missing; install the GCC 15 C++ development package")
endif()
file(READ "${std_metadata}" std_modules)
string(JSON std_source GET "${std_modules}" modules 0 source-path)
get_filename_component(std_source_directory "${std_source}" DIRECTORY)
add_library(crypto_std STATIC)
target_sources(crypto_std PUBLIC
    FILE_SET CXX_MODULES BASE_DIRS "${std_source_directory}" FILES "${std_source}")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
include(CTest)
add_subdirectory(src)
add_subdirectory(apps)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

