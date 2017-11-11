cmake_minimum_required(VERSION 3.8)
project(feather-example)

set (CMAKE_CXX_STANDARD 11)
add_definitions("-Wall -Werror")

set(SOURCE ft_profiler.c)
add_executable(${PROJECT_NAME} ${SOURCE})