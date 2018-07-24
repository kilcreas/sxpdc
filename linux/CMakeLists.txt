cmake_minimum_required (VERSION 2.6)

find_package(PkgConfig)
pkg_check_modules(EVENT REQUIRED libevent>=2.0)
pkg_check_modules(EVENT_PTHREADS REQUIRED libevent_pthreads)
pkg_check_modules(CONFIG REQUIRED libconfig)
pkg_check_modules(BSD REQUIRED libbsd)

find_library(PTHREAD_LIB NAMES pthread)
if (${PTHREAD_LIB} STREQUAL "PTHREAD-NOTFOUND")
    message(FATAL_ERROR "cannot find pthread library, abort.")
else()
    message("found pthread ${PTHREAD_LIB}")
endif()

set(PLATFORM_SPECIFIC_LIBRARIES platform_tools_lib;${PTHREAD_LIB};${EVENT_LIBRARIES};${BSD_LIBRARIES};${CONFIG_LIBRARIES} CACHE string "platform specific libraries" FORCE)
set(TEST_PLATFORM_SPECIFIC_LIBRARIES test_platform_tools_lib;${PTHREAD_LIB};${EVENT_LIBRARIES};${EVENT_PTHREADS_LIBRARIES};${BSD_LIBRARIES};${CONFIG_LIBRARIES} CACHE string "test platform specific libraries" FORCE)

subdirs(src test)
