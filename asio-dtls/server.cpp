#define ASIO_STANDALONE 1
#define ASIO_HEADER_ONLY 1

#include "asio/dtls.hpp"
#include <boost/asio.hpp>
#include <functional>
#include <iostream>
#include <boost/beast/core/detail/base64.hpp>
#include "kcp_dtls.h"
#include "DTLS_Context.h"

#define COOKIE_SECRET_LENGTH 32
int cookie_initialized = 0;
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];

std::string GenBase64_from_ep(const boost::asio::ip::udp::endpoint &ep)
{
	if (!cookie_initialized) {
		if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH)) {
			printf("error setting random cookie secret\n");
			return "";
		}
		cookie_initialized = 1;
	}
	char buffer[256];
	char result[256];
	unsigned int resultlength;

	uint16_t port = ep.port();

	int length = 0;
	memcpy(buffer + length, &port, 2);
	length += 2;

	if (ep.data()->sa_family == AF_INET) {
		auto ipBin = ep.address().to_v4().to_bytes();
		memcpy(buffer + length, &ipBin[0], 4);
		length += 4;
	} else if (ep.data()->sa_family == AF_INET6) {
		auto ipBin = ep.address().to_v6().to_bytes();
		memcpy(buffer + length, &ipBin[0], 16);
		length += 4;
	} else {
		printf("ep protocol error\n");
		return "";
	}

	::HMAC(EVP_sha1(), (const void *)cookie_secret, COOKIE_SECRET_LENGTH,
	       (const unsigned char *)buffer, length, (unsigned char *)result, &resultlength);

	int maxlen = boost::beast::detail::base64::encode(buffer, result, resultlength);

	buffer[maxlen] = 0;
	return std::string(buffer, maxlen);
}

bool generateCookie(std::string &cookie, const boost::asio::ip::udp::endpoint &ep)
{
	cookie = GenBase64_from_ep(ep);

	if (cookie == "") {
		return false;
	}

	return true;
}

bool verifyCookie(const std::string &cookie, const boost::asio::ip::udp::endpoint &ep)
{
	return (cookie == GenBase64_from_ep(ep));
}

class Servers {
    public:
	Servers(boost::asio::io_context &context,
		std::shared_ptr<DTLS_Context> insocks)
		: kcp(context), dtls_sock(insocks)
	{
		dtls_sock->start();
		dtls_sock->exit_cb = [this]() {
			delete this;
		};
		set_kcpcb_to_dtls();
		set_dtlsrd_to_kcp_input(nullptr);
		set_kcp_read_cb();
	}

	void set_kcp_read_cb()
	{
		kcp.async_read_kcp(recvbuff, 1500, [this](const char *buff, int len) {
			if (len > 0) {
				recvbuff[len] = 0;
				printf("kcp read = %d,%s\n", len, buff);
				set_kcp_read_cb();
			} else {
				BOOST_LOG_TRIVIAL(info) << boost::format("kcp async read error %d") % len;
			}
		});
	}

	void set_dtlsrd_to_kcp_input(std::shared_ptr<std::array<char, 1500> > buffer)
	{
		if (!buffer) {
			buffer = std::make_shared<std::array<char, 1500> >();
		}

		dtls_sock->async_read(buffer->data(), buffer->size(), [this, buffer](const char *dat, int length) {
			if (length > 0) {
				kcp.async_input_kcp(dat, length, [buffer](const char *dat, int length) {});
				set_dtlsrd_to_kcp_input(nullptr);
			} else {
				BOOST_LOG_TRIVIAL(info) << boost::format("dtls read fail");
				//dtls read 失败
			}
		});
	}

	void set_kcpcb_to_dtls()
	{
		kcp.output_cb = [this](const char *buf, int len) {
			auto buffer = std::make_shared<std::array<char, 1500> >();
			std::copy(buf, buf + len, buffer->data());
			dtls_sock->async_write(buffer->data(), len, [buffer](const char *buff, int len) {});
		};
	}
	std::shared_ptr<DTLS_Context> dtls_sock;
	kcp_context kcp;
	char recvbuff[1500];
};

template <typename DatagramSocketType>
class DTLS_Server {
    public:
	typedef std::vector<char> buffer_type;
	typedef boost::asio::detail::shared_ptr<buffer_type> buffer_ptr;

	DTLS_Server(boost::asio::io_context &serv,
		    boost::asio::ssl::dtls::context &ctx,
		    typename DatagramSocketType::endpoint_type &ep)
		: m_acceptor(serv, ep), ctx_(ctx), io_ctx(serv)
	{
		m_acceptor.set_option(boost::asio::socket_base::reuse_address(true));

		m_acceptor.set_cookie_generate_callback(generateCookie);
		m_acceptor.set_cookie_verify_callback(verifyCookie);

		m_acceptor.bind(ep);
	}

	void listen()
	{
		auto sock = std::make_shared<boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket> >(io_ctx, ctx_);

		buffer_ptr buffer(new buffer_type(1500));

		boost::asio::error_code ec;

		m_acceptor.async_accept(
			*sock,
			boost::asio::buffer(buffer->data(), buffer->size()),
			[this, sock, buffer](const boost::asio::error_code &ec, size_t size) {
				if (ec) {
					std::cout << "Error in Accept: " << ec.message() << std::endl;
				} else {
					auto callback =
						[this, sock, buffer](const boost::system::error_code &ec, size_t) {
							handshake_completed(sock, ec);
						};

					sock->async_handshake(boost::asio::ssl::stream_base::server,
							      boost::asio::buffer(buffer->data(), size),
							      callback);
				}
				listen();
			},
			ec);
		if (ec) {
			std::cout << "Failed: " << ec.message() << std::endl;
		}
	}

    private:
	void handshake_completed(std::shared_ptr<boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket> > sock, const boost::asio::error_code &ec)
	{
		if (ec) {
			std::cout << "Handshake Error: " << ec.message() << std::endl;
		} else {
			auto ep = sock->next_layer().remote_endpoint();
			std::cout << "Handshake ok = " << ep.address().to_string() << "port = " << ep.port() << std::endl;
			new Servers(io_ctx,std::make_shared<DTLS_Context>(io_ctx, sock));
		}
	}

	boost::asio::ssl::dtls::acceptor<DatagramSocketType> m_acceptor;
	boost::asio::ssl::dtls::context &ctx_;
	boost::asio::io_context &io_ctx;
};

int main()
{
	try {
		boost::asio::io_context context;

		auto listenAddress = boost::asio::ip::address::from_string("0.0.0.0");
		boost::asio::ip::udp::endpoint listenEndpoint(listenAddress, 8888);

		boost::asio::ssl::dtls::context ctx(boost::asio::ssl::dtls::context::dtls_server);

		ctx.set_options(boost::asio::ssl::dtls::context::cookie_exchange);

		auto pass = [](std::size_t size, boost::asio::ssl::context_base::password_purpose purpose) {
			return "12138";
		};

		ctx.set_password_callback(pass);

		ctx.load_verify_file("ca/ca.cer");
		ctx.set_verify_mode(SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_PEER);

		ctx.use_certificate_file("server/pri.ca", boost::asio::ssl::context_base::pem);
		ctx.use_private_key_file("server/pri_key.pem", boost::asio::ssl::context_base::pem);

		DTLS_Server<boost::asio::ip::udp::socket> server(context, ctx, listenEndpoint);
		server.listen();

		context.run();
	} catch (std::exception &ex) {
		std::cerr << "Error: " << ex.what() << std::endl;
	}

	return 0;
}
