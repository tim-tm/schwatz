add_executable(schwatz-server src/main.c)
set_property(TARGET schwatz-server PROPERTY C_STANDARD 99)
target_link_libraries(schwatz-server pthread)
