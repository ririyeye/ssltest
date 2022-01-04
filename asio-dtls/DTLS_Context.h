#ifndef __DTLS_Context__
#define __DTLS_Context__

#include "asio/dtls.hpp"
#include <boost/asio.hpp>
#include <functional>
#include <iostream>
#include <boost/beast/core/detail/base64.hpp>
#include <boost/asio/async_result.hpp>

class DTLS_Context
	: public std::enable_shared_from_this<DTLS_Context> {
    public:
	typedef boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket> dtls_sock;
	typedef std::shared_ptr<dtls_sock> dtls_sock_ptr;

	typedef std::vector<char> buffer_type;
	typedef boost::asio::detail::shared_ptr<buffer_type> buffer_ptr;

	DTLS_Context(boost::asio::io_context &serv, dtls_sock_ptr this_ptr)
		: m_strand(serv), m_socket(this_ptr), m_timer(serv), m_close(serv)
	{
	}

	void start()
	{
		start_read();
		start_timer();
	}

	virtual ~DTLS_Context()
	{
		printf("destruct DTLS_Context!!!\n");
	}

	void write_data(char *dat, int length)
	{
		auto sndbuf = std::make_shared<std::vector<char> >(length);
		std::copy(dat, dat + length, sndbuf->begin());

		auto nullact = [this, sndbuf](boost::system::error_code ec, std::size_t length) {
		};

		m_socket->async_send(boost::asio::buffer(*sndbuf), boost::asio::bind_executor(m_strand, nullact));
	}

	virtual void read_data_cb(char *buff, int length)
	{
	}

	void shutdown()
	{
		if (shutdown_flg == 0) {
			shutdown_flg = 1;
			auto self(shared_from_this());
			auto shutcb = [this, self](boost::system::error_code ec) {
				m_close.cancel();
				printf("shutdonw callback!!!\n");
			};

			m_socket->async_shutdown(boost::asio::bind_executor(m_strand, shutcb));

			//设定强制关闭
			m_timer.expires_from_now(boost::posix_time::seconds(5));
			auto timercb = [this, self](boost::system::error_code ec) {
				if (!ec) {
					printf("force shutdown\n");
					m_socket->next_layer().close();
				}
			};
			m_close.async_wait(boost::asio::bind_executor(m_strand, timercb));
		}
	}

	void start_timer()
	{
		m_timer.expires_from_now(boost::posix_time::seconds(5));
		auto self(shared_from_this());
		auto timercb = [this, self](boost::system::error_code ec) {
			if (!ec) {
				printf("time out!!!\n");
				shutdown();
			}
		};

		m_timer.async_wait(boost::asio::bind_executor(m_strand, timercb));
	}

	void start_read()
	{
		auto self(shared_from_this());

		auto _onrd = [this, self](boost::system::error_code ec, std::size_t length) {
			if (!ec) {
				read_data_cb(recv_buff, length);
				start_timer();
				start_read();
			}
		};

		m_socket->async_receive(boost::asio::buffer(recv_buff), boost::asio::bind_executor(m_strand, _onrd));
	}

    private:
	char recv_buff[1500];
	dtls_sock_ptr m_socket;
	boost::asio::io_context::strand m_strand;
	boost::asio::deadline_timer m_timer;
	boost::asio::deadline_timer m_close;
	int shutdown_flg = 0;
};

#endif