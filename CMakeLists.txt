cmake_minimum_required(VERSION 2.8.9)
project(rsa-server)

enable_testing()

include_directories(include)

file(GLOB_RECURSE src "src/*".cc)

set (CMAKE_CXX_STANDARD 17)
SET(GCC_COVERAGE_LINK_FLAGS    "-pthread -lboost_system")
SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")

add_executable(rsa-server ${src})
install(TARGETS rsa-server RUNTIME DESTINATION bin)
