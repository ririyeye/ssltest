cmake_minimum_required(VERSION 3.0)

PROJECT(ssltest)

option(CMAKE_VERBOSE_MAKEFILE "make verbose=1" OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")


add_executable(ssltest main.cpp)
target_link_libraries(ssltest
    PUBLIC 	
    ssl 
	crypto
	pthread)
