cmake_minimum_required(VERSION 3.0)

PROJECT(ssltest)

option(CMAKE_VERBOSE_MAKEFILE "make verbose=1" OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_compile_options("-g3")

add_executable(ssl-server server.cpp)

target_link_libraries(ssl-server
	PUBLIC
	ssl
	crypto
	pthread)



add_executable(ssl-client client.cpp)

target_link_libraries(ssl-client
	PUBLIC
	ssl
	crypto
	pthread)

add_executable(dtls-server dtls-server.cpp)

target_link_libraries(dtls-server
	PUBLIC
	ssl
	crypto
	pthread)

add_executable(dtls-client dtls-client.cpp)

target_link_libraries(dtls-client
	PUBLIC
	ssl
	crypto
	pthread)

add_executable(dtls-libevent-server dtls-libevent-server.cpp)

target_link_libraries(dtls-libevent-server
	PUBLIC
	event
	ssl
	crypto
	event_openssl
	pthread)

add_executable(dtls-libuv-server dtls-libuv-server.cpp)

target_link_libraries(dtls-libuv-server
	PUBLIC
	ssl
	crypto
	uv
	pthread)

add_subdirectory(mbed)