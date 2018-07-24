include_directories("${PROJECT_SOURCE_DIR}/inc")

add_test_executable (radix1 radix1.c ${PROJECT_SOURCE_DIR}/src/radix.c)

#target_compile_features(radix1 PRIVATE c_variadic_macros c_function_prototypes c_restrict)

add_test (radix1 radix1)
