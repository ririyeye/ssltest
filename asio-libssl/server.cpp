

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

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <list>
#include <vector>

using boost::asio::awaitable;
using boost::asio::co_spawn;
using boost::asio::detached;
using boost::asio::use_awaitable;
using boost::asio::ip::tcp;
namespace this_coro = boost::asio::this_coro;
namespace asio      = boost::asio;

using boost::asio::ip::udp;
enum OVERLAPPED_TYPE {
    RECV = 0,
    SEND,
};
class udp_server : public std::enable_shared_from_this<udp_server> {
public:
    udp_server(boost::asio::io_service& in_ios, udp::endpoint& local, udp::endpoint& inremote, SSL_CTX* ctx)
        : m_ios(in_ios), _socket(m_ios), remote(inremote)
    {
        _socket.open(local.protocol());
        _socket.set_option(udp::socket::reuse_address(true));
        _socket.bind(local);
        _socket.connect(remote);

        ssl       = SSL_new(ctx);
        bio[SEND] = BIO_new(BIO_s_mem());
        bio[RECV] = BIO_new(BIO_s_mem());

        BIO_set_mem_eof_return(bio[SEND], -1);
        BIO_set_mem_eof_return(bio[RECV], -1);
        SSL_set_bio(ssl, bio[RECV], bio[SEND]);
        DTLS_set_link_mtu(ssl, 1400);
        SSL_set_accept_state(ssl);
    }

    void first_receive_proc(char* buff, int len)
    {
        BIO_write(bio[RECV], buff, len);

        co_spawn(
            m_ios,
            [&, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                co_await receive_loop();
                co_return;
            },
            detached);
    }

    ~udp_server()
    {
        std::cout << "close = " << remote << std::endl;
        SSL_free(ssl);
    }

private:
    awaitable<int> send_bio_data()
    {
        do {
            int num = BIO_pending(bio[SEND]);
            if (num <= 0) {
                co_return -1;
            }

            char sdbuff[4096];
            int  wrlen = BIO_read(bio[SEND], sdbuff, 4096);
            if (wrlen > 0) {
                int ret = co_await _socket.async_send(asio::buffer(sdbuff, wrlen), use_awaitable);
            }
        } while (1);
    }
    void ShowCerts(SSL* ssl)
    {
        X509* cert;
        char* line;

        cert = SSL_get_peer_certificate(ssl);
        // SSL_get_verify_result()是重点，SSL_CTX_set_verify()只是配置启不启用并没有执行认证，调用该函数才会真证进行证书认证
        // 如果验证不通过，那么程序抛出异常中止连接
        if (SSL_get_verify_result(ssl) == X509_V_OK) {
            printf("证书验证通过\n");
        }
        if (cert != NULL) {
            printf("数字证书信息:\n");
            line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
            printf("证书: %s\n", line);
            free(line);
            line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
            printf("颁发者: %s\n", line);
            free(line);
            X509_free(cert);
        } else
            printf("无证书信息！\n");
    }
    awaitable<void> receive_loop(void)
    {
        char buff[1500];
        int  ssl_error;
        while (true) {
            int bytes = 0;
            do {
                char sslrd[4096];
                bytes         = SSL_read(ssl, sslrd, 4096);
                int ssl_error = SSL_get_error(ssl, bytes);

                if (bytes > 0) {
                    app_recv.emplace_back(sslrd, sslrd + bytes);
                    sslrd[bytes] = 0;
                    printf("get data %d = %s\n", bytes, sslrd);
                }

                if (!connected_flg && SSL_is_init_finished(ssl)) {
                    connected_flg = 1;
                    ShowCerts(ssl);
                    printf("handshake ok !!\n");
                }

                if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                    co_await send_bio_data();
                } else if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                    std::cout << "remote close!!" << std::endl;
                    co_return;
                } else if (ssl_error == SSL_ERROR_SSL) {
                    std::cout << "remote ssl error!!" << std::endl;
                    co_return;
                } else if (ssl_error) {
                    std::cout << "error = " << ssl_error << std::endl;
                }
            } while (bytes > 0);

            int len = co_await _socket.async_receive(asio::buffer(buff), use_awaitable);

            BIO_write(bio[RECV], buff, len);
        }
    }
    udp::endpoint                remote;
    boost::asio::io_service&     m_ios;
    udp::socket                  _socket;
    SSL*                         ssl;
    BIO*                         bio[2];
    std::list<std::vector<char>> app_recv;

    int connected_flg = 0;
};

awaitable<void> listener(boost::asio::io_service& ios, int port, SSL_CTX* ctx)
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

        auto sock = std::make_shared<udp_server>(ios, ep, tmpep, ctx);
        sock->first_receive_proc(buff, len);
    }
}
SSL_CTX* create_context();
void     configure_context(SSL_CTX* ctx);
int      main()
{
    SSL_library_init();

    OpenSSL_add_all_algorithms();

    SSL_load_error_strings();

    auto ctx = create_context();
    configure_context(ctx);

    boost::asio::io_service io_context;

    int port = 8888;

    co_spawn(io_context, listener(io_context, port, ctx), detached);

    io_context.run();

    port++;
}
