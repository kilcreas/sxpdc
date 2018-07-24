cmake_minimum_required (VERSION 2.6)
project(sxpd C)

if(NOT DEFINED TARGET_BUILD_PLATFORM)
    message(FATAL_ERROR "TARGET_BUILD_PLATFORM is not set, abort.")
endif()

set(TARGET_BUILD_PLATFORM_DIR "${PROJECT_SOURCE_DIR}/${TARGET_BUILD_PLATFORM}")

if(NOT IS_DIRECTORY ${TARGET_BUILD_PLATFORM_DIR} )
    message(FATAL_ERROR "${TARGET_BUILD_PLATFORM_DIR} directory does not exist, abort.")
endif()

enable_testing()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    # code coverage testing setup
    include(CodeCoverage.cmake)
    
    # memory check testing setup
    find_program(CTEST_MEMORYCHECK_COMMAND NAMES valgrind)
    set(MEMORYCHECK_COMMAND_OPTIONS "--leak-check=full --max-stackframe=3100000")
    INCLUDE(Dart)
else()
    message("CMAKE_BUILD_TYPE not set to \"Debug\", build will not contain memory and coverage testing.")
    set(CMAKE_C_FLAGS_COVERAGE "")
    set(GCOV_LIB "")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -pedantic -Wextra -std=gnu99 -DSXP_USE_SETJMP")

# macro used to add new test executable, link testing libraries and add gnu coverage compilation flags
macro(add_test_executable _name)
    add_executable(${ARGV})
    target_link_libraries(${_name} test_topo_lib sxpd_lib_testing
                          ${TEST_PLATFORM_SPECIFIC_LIBRARIES} sxpd_lib_testing
                          ${GCOV_LIB})
    set_target_properties(${_name} PROPERTIES COMPILE_FLAGS
                          "${COMPILE_FLAGS} -DTESTING ${CMAKE_C_FLAGS_COVERAGE}")
endmacro()

#${TARGET_BUILD_PLATFORM_DIR} must be first as it sets platform-specific libraries variable ENV{PLATFORM_LINK_LIBRARIES} (used by tests)
subdirs(${TARGET_BUILD_PLATFORM_DIR} src test )
