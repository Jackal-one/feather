cmake_minimum_required(VERSION 3.8)
project(feather-example)

add_definitions("-W")
add_executable(${PROJECT_NAME} main.cc)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_range_for)