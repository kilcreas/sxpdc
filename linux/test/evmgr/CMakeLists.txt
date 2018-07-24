include_directories("${PROJECT_SOURCE_DIR}/inc")

add_test_executable (evmgr_socket evmgr_socket.c)

#target_compile_features(evmgr_socket PRIVATE c_variadic_macros c_function_prototypes c_restrict)

add_test (evmgr_socket evmgr_socket)
