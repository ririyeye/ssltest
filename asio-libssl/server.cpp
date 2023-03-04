

#include <arpa/inet.h>
#include <array>
#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/write.hpp>
#include <cstdio>
#include <iostream>
#include <string>

using boost::asio::awaitable;
using boost::asio::co_spawn;
using boost::asio::detached;
using boost::asio::use_awaitable;
using boost::asio::ip::tcp;
namespace this_coro = boost::asio::this_coro;
namespace asio      = boost::asio;

using boost::asio::ip::udp;

class udp_server : public std::enable_shared_from_this<udp_server> {
public:
    udp_server(boost::asio::io_service& in_ios, udp::endpoint& local, udp::endpoint& inremote)
        : m_ios(in_ios), _socket(m_ios), remote(inremote)
    {
        _socket.open(local.protocol());
        _socket.set_option(udp::socket::reuse_address(true));
        _socket.bind(local);
        _socket.connect(remote);
    }

    awaitable<void> first_receive_proc(char* buff, int len)
    {

        std::cout << "first recv:" << remote << std::endl;
        int ret = co_await _socket.async_send(asio::buffer(buff, len), use_awaitable);

        co_spawn(
            m_ios,
            [&, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                // auto self(shared_from_this());
                char buff[1500];
                while (true) {

                    int len = co_await _socket.async_receive(asio::buffer(buff), use_awaitable);
                    std::cout << "post recv:" << remote << std::endl;

                    int ret = co_await _socket.async_send(asio::buffer(buff, len), use_awaitable);
                    break;
                }
            },
            detached);
    }
    ~udp_server() { std::cout << "close = " << remote << std::endl; }

private:
    awaitable<void> receive_loop(void)
    {
        auto self(shared_from_this());
        char buff[1500];
        while (true) {

            int len = co_await _socket.async_receive_from(asio::buffer(buff), remote, use_awaitable);
            std::cout << "post recv:" << remote << std::endl;

            int ret = co_await _socket.async_send(asio::buffer(buff, len), use_awaitable);
        }
    }
    udp::endpoint            remote;
    boost::asio::io_service& m_ios;
    udp::socket              _socket;
};

awaitable<void> listener(boost::asio::io_service& ios, int port)
{
    char        buff[1500];
    auto        ep = udp::endpoint(udp::v4(), port);
    udp::socket socket(ios);
    socket.open(ep.protocol());
    boost::system::error_code ec;
    socket.set_option(udp::socket::reuse_address(true), ec);

    socket.bind(ep);

    for (;;) {
        udp::endpoint tmpep;

        int len = co_await socket.async_receive_from(asio::buffer(buff), tmpep, use_awaitable);

        auto sock = std::make_shared<udp_server>(ios, ep, tmpep);
        co_await sock->first_receive_proc(buff, len);
    }
}

int main()
{
    boost::asio::io_service io_context;

    int port = 22222;

    co_spawn(io_context, listener(io_context, port), detached);

    io_context.run();

    port++;
}
