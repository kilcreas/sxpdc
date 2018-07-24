include_directories("${PROJECT_SOURCE_DIR}/inc")

add_test_executable (coverage_1 coverage_1.c)

add_test_executable (coverage_2_loop_detect coverage_2_loop_detect.c)

add_test_executable (hold_time_negotiation hold_time_negotiation.c)

add_test_executable (topology_6_3_1 topology_6_3_1.c)

add_test_executable (topology_6_3_2 topology_6_3_2.c)

add_test_executable (topology_6_3_3 topology_6_3_3.c)

add_test_executable (topology_6_4_1 topology_6_4_1.c)

add_test_executable (topology_6_4_2 topology_6_4_2.c)

add_test_executable (topology_6_4_3 topology_6_4_3.c)

add_test_executable (topology_6_4_4 topology_6_4_4.c)

add_test_executable (topology_6_4_5 topology_6_4_5.c)

add_test_executable (topology_6_5_1 topology_6_5_1.c)

add_test_executable (topology_6_5_2 topology_6_5_2.c)

add_test_executable (topology_6_5_3 topology_6_5_3.c)

add_test_executable (topology_6_5_4 topology_6_5_4.c)

add_test_executable (topology_6_5_5 topology_6_5_5.c)

add_test_executable (topology_6_8_2 topology_6_8_2.c)

add_test_executable (topology_6_8_3 topology_6_8_3.c)

add_test_executable (topology_6_9_1 topology_6_9_1.c)

add_test_executable (topology_6_9_2 topology_6_9_2.c)

add_test_executable (topology_6_10_1 topology_6_10_1.c)

add_test_executable (cj_topo_1 cj_topo_1.c)

add_test_executable (cj_topo_2 cj_topo_2.c)

add_test_executable (cj_topo_3 cj_topo_3.c)

add_test_executable (cj_topo_4 cj_topo_4.c)

add_test_executable (cj_topo_5 cj_topo_5.c)

add_test_executable (cj_topo_6 cj_topo_6.c)

add_test_executable (cj_topo_7 cj_topo_7.c)

add_test_executable (cj_topo_8 cj_topo_8.c)

add_test_executable (cj_topo_9 cj_topo_9.c)

add_custom_command(TARGET topology_6_3_1 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${TARGET_BUILD_PLATFORM_DIR}/test/topology/default.cfg"
        $<TARGET_FILE_DIR:topology_6_3_1>
        COMMENT "copying configuration files for topology tests")

add_test (coverage_1 coverage_1)

add_test (coverage_2_loop_detect coverage_2_loop_detect)

add_test (hold_time_negotiation hold_time_negotiation)

add_test (topology_6_3_1 topology_6_3_1)

add_test (topology_6_3_2 topology_6_3_2)

add_test (topology_6_3_3 topology_6_3_3)

add_test (topology_6_4_1 topology_6_4_1)

add_test (topology_6_4_2 topology_6_4_2)

add_test (topology_6_4_3 topology_6_4_3)

add_test (topology_6_4_4 topology_6_4_4)

add_test (topology_6_4_5 topology_6_4_5)

add_test (topology_6_5_1 topology_6_5_1)

add_test (topology_6_5_2 topology_6_5_2)

add_test (topology_6_5_3 topology_6_5_3)

add_test (topology_6_5_4 topology_6_5_4)

add_test (topology_6_5_5 topology_6_5_5)

add_test (topology_6_8_2 topology_6_8_2)

add_test (topology_6_8_3 topology_6_8_3)

add_test (topology_6_9_1 topology_6_9_1 380)

add_test (topology_6_9_2 topology_6_9_2 128 256)

add_test (topology_6_10_1 topology_6_10_1)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    setup_target_for_coverage(sxpd_coverage ctest coverage)
endif()
