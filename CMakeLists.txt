cmake_minimum_required(VERSION 3.9)
project(dtrace_playground)

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_CXX_FLAGS "-g")

# set(CMAKE_CXX_FLAGS "-mmacosx-version-min=10.9")

add_executable(dtrace_playground pipe.cpp)
# add_executable(dtrace_playground other.cpp)

target_link_libraries(dtrace_playground dtrace)