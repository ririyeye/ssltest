#define ASIO_STANDALONE 1
#define ASIO_HEADER_ONLY 1

#include "asio/dtls.hpp"
#include <boost/asio.hpp>
#include <functional>
#include <iostream>
#include <boost/beast/core/detail/base64.hpp>
#include "kcp_dtls.h"

class Client {
    public:
	Client(boost::asio::io_context &context,
	       boost::asio::ssl::dtls::context &ctx,
	       boost::asio::ip::udp::endpoint &ep)
		: io_ctx(context), ctx_(ctx), m_ep(ep)
		,m_shake_timer(io_ctx)
	{
		connect();
	}

	void kcp_start()
	{
		kcp->start();
		const char *test = "hello\n";
		kcp->write_data(test, strlen(test));
	}

	void kcp_exit_cb()
	{
		printf("kcp exit!!! reconnect\n");
		connect();
	}

	void connect()
	{
		auto sock = std::make_shared<boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket> >(io_ctx, ctx_);
		sock->lowest_layer().connect(m_ep);

		auto shakecb = [this, sock](boost::system::error_code ec) {
			if (!ec) {
				kcp = std::make_shared<kcp_Context>(io_ctx, sock);
				kcp->exit_cb = std::bind(&Client::kcp_exit_cb, this);
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

	boost::asio::ssl::dtls::context &ctx_;
	boost::asio::io_context &io_ctx;
	boost::asio::ip::udp::endpoint &m_ep;
	std::shared_ptr<kcp_Context> kcp;
	boost::asio::deadline_timer m_shake_timer;
};

int main()
{
	try {
		boost::asio::io_context context;

		auto serverAddress = boost::asio::ip::address::from_string("127.0.0.1");
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
