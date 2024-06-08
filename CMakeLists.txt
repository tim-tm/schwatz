cmake_minimum_required(VERSION 3.5)
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

project(schwatz)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -Wall -Wextra")

add_subdirectory(schwatz)
add_subdirectory(schwatz-server)
