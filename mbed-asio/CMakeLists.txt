

add_compile_options("-g3")

add_executable(mbed-server mbed_cfg.cpp server.cpp mbed_asio.cpp)

target_link_libraries(mbed-server
	PUBLIC
	mbedtls
	mbedx509
	mbedcrypto
	pthread)


add_executable(mbed-client mbed_cfg.cpp client.cpp mbed_asio.cpp)

target_link_libraries(mbed-client
	PUBLIC
	mbedtls
	mbedx509
	mbedcrypto
	pthread)
