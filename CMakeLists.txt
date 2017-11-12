cmake_minimum_required(VERSION 3.8)
project(feather-example)

add_definitions("-Wall -Werror")
add_executable(${PROJECT_NAME} main.cc ft_profiler.c)
set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)