cmake_minimum_required(VERSION 3.3)
project(minimr)

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_library(minimr STATIC minimr.h minimr.c)

add_executable(minimr-cli-demo EXCLUDE_FROM_ALL cli-demo.cpp)
target_link_libraries(minimr-cli-demo minimr)