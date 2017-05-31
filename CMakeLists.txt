cmake_minimum_required(VERSION 2.8)
project(libEpollSSL)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++11")

set(SOURCE_FILES
    EpollSSL.cpp
    EpollSSL.hpp EpollThread.cpp Server.cpp IOWrapper.cpp)

add_library(EpollSSL ${SOURCE_FILES} Test.cpp)
add_library(EpollSSL_static STATIC ${SOURCE_FILES})
set_target_properties(EpollSSL_static PROPERTIES OUTPUT_NAME EpollSSL)

install(FILES EpollSSL.hpp DESTINATION include/EpollSSL/EpollSSL.hpp)
install(TARGETS EpollSSL EpollSSL_static DESTINATION lib)

add_executable(EpollSSL_Test Test.cpp)
target_link_libraries(EpollSSL_Test EpollSSL ssl crypto pthread)
set_property(SOURCE Test.cpp APPEND_STRING PROPERTY COMPILE_FLAGS " -I. ")