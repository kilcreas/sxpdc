include_directories("${PROJECT_SOURCE_DIR}/inc")

add_test_executable (sxpd1 sxpd1.c)
#target_compile_features(sxpd1 PRIVATE c_variadic_macros c_function_prototypes c_restrict)
add_test (sxpd1 sxpd1)

add_test_executable (sxpd2 sxpd2.c)
#target_compile_features(sxpd2 PRIVATE c_variadic_macros c_function_prototypes c_restrict)
add_test (sxpd2 sxpd2)
