cmake_minimum_required (VERSION 2.6)

include_directories("${PROJECT_SOURCE_DIR}/inc")

if(NOT DEFINED ENABLE_LOG_PRINTING)
    message("ENABLE_LOG_PRINTING not defined, log messages will be sent to syslog ONLY.")
elseif(${ENABLE_LOG_PRINTING} STREQUAL "false")
    message("ENABLE_LOG_PRINTING set to false, log messages will be sent to syslog ONLY.")
else()
    message("ENABLE_LOG_PRINTING defined, log messages will be sent to syslog AND printed to console.")
    add_definitions(-DENABLE_LOG_PRINTING)
endif()



if(NOT DEFINED ENABLE_STRICT_BINDING_CFG_CHECK)
    message("ENABLE_STRICT_BINDING_CFG_CHECK not defined, binding configuration strict checker is enabled.")
    add_definitions(-DENABLE_STRICT_BINDING_CFG_CHECK)
elseif(${ENABLE_STRICT_BINDING_CFG_CHECK} STREQUAL "false")
    message("ENABLE_STRICT_BINDING_CFG_CHECK set to false, binding configuration strict checker is disabled.")
else()
    message("ENABLE_STRICT_BINDING_CFG_CHECK defined, binding configuration strict checker is enabled.")
    add_definitions(-DENABLE_STRICT_BINDING_CFG_CHECK)
endif()



add_library (platform_tools_lib STATIC 
             ${TARGET_BUILD_PLATFORM_DIR}/src/evmgr.c
             ${TARGET_BUILD_PLATFORM_DIR}/src/mem.c
             ${TARGET_BUILD_PLATFORM_DIR}/src/config_validate.c
             ${TARGET_BUILD_PLATFORM_DIR}/src/config.c
             ${TARGET_BUILD_PLATFORM_DIR}/src/timestamp.c
             ${TARGET_BUILD_PLATFORM_DIR}/src/rnd.c
             ${TARGET_BUILD_PLATFORM_DIR}/src/logging.c)
             
add_library (test_platform_tools_lib STATIC ${TARGET_BUILD_PLATFORM_DIR}/src/evmgr.c
             ${TARGET_BUILD_PLATFORM_DIR}/src/mem.c
             ${TARGET_BUILD_PLATFORM_DIR}/src/config_validate.c
             ${TARGET_BUILD_PLATFORM_DIR}/src/config.c
             ${TARGET_BUILD_PLATFORM_DIR}/src/timestamp.c
             ${TARGET_BUILD_PLATFORM_DIR}/src/rnd.c
             ${TARGET_BUILD_PLATFORM_DIR}/src/logging.c
             ${TARGET_BUILD_PLATFORM_DIR}/test/framework/src/log_check.c)

set_target_properties (test_platform_tools_lib PROPERTIES COMPILE_FLAGS
                       "${COMPILE_FLAGS} -DTESTING ${CMAKE_C_FLAGS_COVERAGE}")

add_library (test_topo_lib STATIC ${TARGET_BUILD_PLATFORM_DIR}/test/framework/src/topology.c)

set_target_properties (test_topo_lib PROPERTIES COMPILE_FLAGS
                       "${COMPILE_FLAGS} -DTESTING")

if(NOT DEFINED ENABLE_GDBUS_INTERFACE)
    message("ENABLE_GDBUS_INTERFACE not defined, building WITHOUT gdbus interface." )
elseif(${ENABLE_GDBUS_INTERFACE} STREQUAL "false")
    message("ENABLE_GDBUS_INTERFACE set to false, building WITHOUT gdbus interface." )
else()
    find_package(PkgConfig)
    pkg_check_modules(GDBUS REQUIRED gio-2.0 gio-unix-2.0)
    # Creates variables GDBUS_INCLUDE_DIRS, GDBUS_LIBRARY_DIRS and GDBUS_LIBRARIES

    set(GDBUS_GEN_H "${CMAKE_BINARY_DIR}/linux/src/gdbus_interface_gen.h")
    set(GDBUS_GEN_C "${CMAKE_BINARY_DIR}/linux/src/gdbus_interface_gen.c")

    include_directories(${GDBUS_INCLUDE_DIRS} ${CMAKE_BINARY_DIR}/linux/src/)
    add_definitions(-DENABLE_GDBUS_INTERFACE)

    add_custom_command(OUTPUT ${GDBUS_GEN_H} ${GDBUS_GEN_C}
                       COMMAND gdbus-codegen ARGS --interface-prefix com.cisco --generate-c-code gdbus_interface_gen
                       ${CMAKE_CURRENT_SOURCE_DIR}/gdbus_interface.xml
                       WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/linux/src/"
                       COMMENT "generating gdbus_interface.[ch] from gdbus_interface.xml"
                      )

    add_library (gdbus_interface_lib STATIC gdbus_interface.c ${GDBUS_GEN_C})

    target_link_libraries(gdbus_interface_lib ${PTHREAD_LIB} ${GDBUS_LIBRARIES})
    set(PLATFORM_SPECIFIC_LIBRARIES ${PLATFORM_SPECIFIC_LIBRARIES};gdbus_interface_lib;${EVENT_PTHREADS_LIBRARIES} CACHE string "platform specific libraries" FORCE)
    set(TEST_PLATFORM_SPECIFIC_LIBRARIES ${TEST_PLATFORM_SPECIFIC_LIBRARIES};gdbus_interface_lib;${EVENT_PTHREADS_LIBRARIES} CACHE string "test platform specific libraries" FORCE)
endif()

add_executable (sxpd sxpd_main.c)

#target_compile_features(sxpd PRIVATE c_variadic_macros c_function_prototypes c_restrict)

set_target_properties(sxpd PROPERTIES ENABLE_EXPORTS true)

target_link_libraries(sxpd sxpd_lib ${PLATFORM_SPECIFIC_LIBRARIES})
