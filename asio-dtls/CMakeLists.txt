

add_compile_options("-g3")

add_subdirectory(asio_dtls_lib)

add_executable(server server.cpp kcp/ikcp.c)
target_link_libraries(server asio_dtls boost_coroutine)


add_executable(client client.cpp kcp/ikcp.c)
target_link_libraries(client asio_dtls boost_coroutine)

