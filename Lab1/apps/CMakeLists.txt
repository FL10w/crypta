add_executable(app1
        main.cpp
)

target_compile_features(app1
        PRIVATE
            cxx_std_23
)

target_link_libraries(app1
        PRIVATE
        lib1
)

set_target_properties(app1
        PROPERTIES
            OUTPUT_NAME crypto
)

add_custom_command(TARGET app1 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_CURRENT_SOURCE_DIR}/../assets" "$<TARGET_FILE_DIR:app1>/demo/assets")
