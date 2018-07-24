include_directories("${PROJECT_SOURCE_DIR}/inc")

add_test_executable (config1 config1.c)

add_test_executable (default_settings default_settings.c)

add_custom_command(TARGET config1 POST_BUILD           # Adds a post-build event to test config1
    COMMAND ${CMAKE_COMMAND} -E copy_if_different      # which executes "cmake - E copy_if_different..."
        "${TARGET_BUILD_PLATFORM_DIR}/test/config/config1.cfg"   # <--this is in-file
        $<TARGET_FILE_DIR:config1>                     # <--this is out-file path
        COMMENT "copying configuration test files")

add_custom_command(TARGET config1 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${TARGET_BUILD_PLATFORM_DIR}/test/config/config2.cfg"
        $<TARGET_FILE_DIR:config1>)

add_custom_command(TARGET config1 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${TARGET_BUILD_PLATFORM_DIR}/test/config/config3.cfg"
        $<TARGET_FILE_DIR:config1>)
        
add_custom_command(TARGET config1 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${TARGET_BUILD_PLATFORM_DIR}/test/config/config4.cfg"
        $<TARGET_FILE_DIR:config1>)
        
add_custom_command(TARGET config1 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${TARGET_BUILD_PLATFORM_DIR}/test/config/config5.cfg"
        $<TARGET_FILE_DIR:config1>)
        
add_custom_command(TARGET config1 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${TARGET_BUILD_PLATFORM_DIR}/test/config/config6.cfg"
        $<TARGET_FILE_DIR:config1>)
        
add_custom_command(TARGET config1 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${TARGET_BUILD_PLATFORM_DIR}/test/config/config7.cfg"
        $<TARGET_FILE_DIR:config1>)

add_custom_command(TARGET config1 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${TARGET_BUILD_PLATFORM_DIR}/test/config/config8.cfg"
        $<TARGET_FILE_DIR:config1>)
        
add_custom_command(TARGET default_settings POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${TARGET_BUILD_PLATFORM_DIR}/test/config/default_settings.cfg"
        $<TARGET_FILE_DIR:default_settings>)

add_test (config1 config1)

add_test (default_settings default_settings)
