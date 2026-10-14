add_library(lib1)

target_compile_features(lib1
        PUBLIC
            cxx_std_23
)

target_sources(lib1
        PUBLIC
            FILE_SET CXX_MODULES FILES
        crypto.bits.cppm
        crypto.cipher.cppm
        crypto.modes.cppm
        crypto.padding.cppm
        crypto.context.cppm
        crypto.feistel.cppm
        crypto.des.cppm
        crypto.deal.cppm
        PRIVATE
        crypto.bits.cpp
        crypto.modes.cpp
        crypto.padding.cpp
        crypto.context.cpp
        crypto.feistel.cpp
        crypto.des.cpp
        crypto.deal.cpp
)

target_link_libraries(lib1 PUBLIC crypto_std Threads::Threads)
