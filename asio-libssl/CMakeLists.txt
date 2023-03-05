

add_compile_options("-g")





add_executable(server server.cpp ssl.cpp)

target_link_libraries(server
	PUBLIC
	ssl
	crypto
	pthread)


