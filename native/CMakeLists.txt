cmake_minimum_required(VERSION 3.16)
project(vectorrift C)

if(NOT CMAKE_C_COMPILER)
  set(CMAKE_C_COMPILER clang-18)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(ENGINE_SOURCES
  src/sha256.c
  src/mutate.c
  src/exec.c
  src/campaign.c
  src/main.c
)

function(vr_add_fuzzer name target_src)
  add_library(${name}_target OBJECT ${target_src})
  target_include_directories(${name}_target PRIVATE ${CMAKE_SOURCE_DIR}/include)
  target_compile_options(${name}_target PRIVATE
    -fsanitize=address,undefined
    -fsanitize-coverage=trace-pc-guard
    -fno-sanitize-recover=all
    -fno-omit-frame-pointer
    -Wall -Wextra -O1 -g
  )
  add_executable(${name} ${ENGINE_SOURCES} $<TARGET_OBJECTS:${name}_target>)
  target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/include)
  target_compile_options(${name} PRIVATE
    -fsanitize=address,undefined
    -fno-sanitize-recover=all
    -fno-omit-frame-pointer
    -Wall -Wextra -O1 -g
  )
  target_link_options(${name} PRIVATE
    -fsanitize=address,undefined
    -fno-sanitize-recover=all
  )
endfunction()

vr_add_fuzzer(vrfuzz_riftpacket targets/riftpacket.c)
vr_add_fuzzer(vrfuzz_hostile targets/hostile.c)

add_executable(riftpacket_libfuzzer targets/riftpacket.c targets/libfuzzer_entry.c)
target_include_directories(riftpacket_libfuzzer PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_compile_options(riftpacket_libfuzzer PRIVATE
  -fsanitize=fuzzer,address,undefined
  -fno-sanitize-recover=all
  -fno-omit-frame-pointer
  -Wall -Wextra -O1 -g
)
target_link_options(riftpacket_libfuzzer PRIVATE
  -fsanitize=fuzzer,address,undefined
  -fno-sanitize-recover=all
)
