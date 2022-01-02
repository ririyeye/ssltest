

add_compile_options("-g3")



set(examples_boost_server_sources main.cpp)



add_executable(example_boost_server ${examples_boost_server_sources})

add_subdirectory(asio_dtls_lib)

target_link_libraries(example_boost_server asio_dtls)


