cmake_minimum_required(VERSION 3.10)
project(caoin_hook C)

# arm64 目标（NDK toolchain）：完整 hook 库
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64")
    add_library(caoin_hook STATIC reloc.c)   # P1 后续: tramp.c writer.c
    target_include_directories(caoin_hook PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
endif()

# 主机端：relocator 纯逻辑单测（不依赖 arm64）
enable_testing()
add_executable(test_reloc tests/test_reloc.c reloc.c)
add_test(NAME reloc COMMAND test_reloc)
