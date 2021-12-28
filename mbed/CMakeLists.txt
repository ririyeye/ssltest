

add_compile_options("-g3")

add_executable(dtls-mbed-server dtls-mbed-server.cpp)

target_link_libraries(dtls-mbed-server
	PUBLIC
	mbedtls
	mbedx509
	mbedcrypto
	uv
	pthread)
