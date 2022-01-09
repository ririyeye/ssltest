#define ASIO_STANDALONE 1
#define ASIO_HEADER_ONLY 1

#include "asio/dtls.hpp"
#include <boost/asio.hpp>
#include <functional>
#include <iostream>
#include <boost/beast/core/detail/base64.hpp>
#include "kcp_dtls.h"
#include "DTLS_Context.h"
class Client {
    public:
	Client(boost::asio::io_context &context,
	       boost::asio::ssl::dtls::context &ctx,
	       boost::asio::ip::udp::endpoint &ep)
		: io_ctx(context), ctx_(ctx), m_ep(ep), m_shake_timer(io_ctx), kcp(io_ctx), kcp_test(context)
	{
		connect();
		set_kcpcb_to_dtls();
	}

    private:
	void kcp_start()
	{
		connected_flg = true;
		dtls_sock->start();		
		set_dtlsrd_to_kcp_input(nullptr);
		//add test 1000ms kcp write
		kcp_test_send();
	}

	void kcp_test_send()
	{
		auto timcb = [this](boost::system::error_code ec) {
			if (!ec) {
				const char *snd = "test kcp send!!!!\n";
				kcp.async_write_kcp(snd, strlen(snd), nullptr);

				kcp_test_send();
			}
		};

		kcp_test.expires_from_now(boost::posix_time::seconds(1));
		kcp_test.async_wait(timcb);
	}

	void kcp_exit_cb()
	{
		connected_flg = false;
		BOOST_LOG_TRIVIAL(warning) << boost::format("dtls exit ,reconnect");
		connect();
	}

	void connect()
	{
		auto sock = std::make_shared<boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket> >(io_ctx, ctx_);
		sock->lowest_layer().connect(m_ep);

		auto shakecb = [this, sock](boost::system::error_code ec) {
			m_shake_timer.cancel();
			if (!ec) {
				dtls_sock = std::make_shared<DTLS_Context>(io_ctx, sock);
				dtls_sock->exit_cb = std::bind(&Client::kcp_exit_cb, this);
				kcp_start();
			} else {
				sock->next_layer().close();
				connect();
				printf("handshake error!!! reconnect \n");
			}
		};

		sock->async_handshake(boost::asio::ssl::stream_base::client, shakecb);

		auto timercb = [this, sock](boost::system::error_code ec) {
			if (!ec) {
				printf("handshake timeout\n");
				sock->next_layer().close();
			}
		};
		m_shake_timer.expires_from_now(boost::posix_time::seconds(5));
		m_shake_timer.async_wait(timercb);
	}

	void set_dtlsrd_to_kcp_input(std::shared_ptr<std::array<char, 1500> > buffer)
	{
		if (!buffer) {
			buffer = std::make_shared<std::array<char, 1500> >();
		}

		dtls_sock->async_read(buffer->data(), buffer->size(), [this, buffer](const char *dat, int length) {
			if (length > 0) {
				if (!connected_flg) {
					set_dtlsrd_to_kcp_input(buffer);
				} else {
					set_dtlsrd_to_kcp_input(nullptr);
					kcp.async_input_kcp(dat, length, [buffer](const char *dat, int length) {});
				}
			} else {
				//dtls read 失败
			}
		});
	}

	void set_kcpcb_to_dtls()
	{
		kcp.output_cb = [this](const char *buf, int len) {
			//dtls还没有连接上 忽略掉
			if (!connected_flg)
				return;
			auto buffer = std::make_shared<std::array<char, 1500> >();
			std::copy(buf, buf + len, buffer->data());
			dtls_sock->async_write(buffer->data(), buffer->size(), [buffer](const char *buff, int len) {});
		};
	}

	boost::asio::deadline_timer kcp_test;

	boost::asio::ssl::dtls::context &ctx_;
	boost::asio::io_context &io_ctx;
	boost::asio::ip::udp::endpoint &m_ep;
	std::shared_ptr<DTLS_Context> dtls_sock;
	boost::asio::deadline_timer m_shake_timer;
	bool connected_flg = false;
	kcp_context kcp;
};

int main()
{
	try {
		boost::asio::io_context context;

		auto serverAddress = boost::asio::ip::address::from_string("216.238.76.114");
		boost::asio::ip::udp::endpoint serverEndpoint(serverAddress, 8888);

		boost::asio::ssl::dtls::context ctx(boost::asio::ssl::dtls::context::dtls_client);

		auto pass = [](std::size_t size, boost::asio::ssl::context_base::password_purpose purpose) {
			return "12138";
		};

		ctx.set_password_callback(pass);

		// ctx.load_verify_file("ca/ca.cer");
		// ctx.set_verify_mode(SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_PEER);

		ctx.use_certificate_file("client/pri.ca", boost::asio::ssl::context_base::pem);
		ctx.use_private_key_file("client/pri_key.pem", boost::asio::ssl::context_base::pem);

		Client client(context, ctx, serverEndpoint);

		context.run();
	} catch (std::exception &ex) {
		std::cerr << "Error: " << ex.what() << std::endl;
	}

	return 0;
}
