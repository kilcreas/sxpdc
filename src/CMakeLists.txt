cmake_minimum_required (VERSION 2.6)

include_directories("${PROJECT_SOURCE_DIR}/inc")

add_library (sxpd_lib STATIC sxp.c sxpd.c debug.c radix.c)

add_library (sxpd_lib_testing STATIC sxp.c sxpd.c debug.c radix.c)

set_target_properties (sxpd_lib_testing PROPERTIES COMPILE_FLAGS
                       "${COMPILE_FLAGS} -DTESTING ${CMAKE_C_FLAGS_COVERAGE}")
