

add_compile_options("-g3")

add_executable(dtls-mbed-server mbed_cfg.cpp server.cpp mbed_uv.cpp)

target_link_libraries(dtls-mbed-server
	PUBLIC
	mbedtls
	mbedx509
	mbedcrypto
	uv
	pthread)


add_executable(dtls-mbed-client mbed_cfg.cpp client.cpp mbed_uv.cpp)

target_link_libraries(dtls-mbed-client
	PUBLIC
	mbedtls
	mbedx509
	mbedcrypto
	uv
	pthread)
