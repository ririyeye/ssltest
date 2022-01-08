#ifndef __DTLS_Context__
#define __DTLS_Context__

#include "asio/dtls.hpp"
#include <boost/asio.hpp>
#include <functional>
#include <iostream>
#include <boost/beast/core/detail/base64.hpp>
#include <boost/asio/async_result.hpp>
#include <alloca.h>
#include <boost/asio/spawn.hpp>
#include <boost/format.hpp>
#include <boost/log/trivial.hpp>

class DTLS_Context
	: public std::enable_shared_from_this<DTLS_Context> {
    public:
	typedef boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket> dtls_sock;
	typedef std::shared_ptr<dtls_sock> dtls_sock_ptr;

	typedef std::vector<char> buffer_type;
	typedef boost::asio::detail::shared_ptr<buffer_type> buffer_ptr;
	std::function<void()> exit_cb;

	DTLS_Context(boost::asio::io_context &serv, dtls_sock_ptr this_ptr)
		: m_strand(serv.get_executor()), m_socket(this_ptr), m_recv_timer(serv), m_close_timer(serv), m_keep_timer(serv)
	{
	}

	void start()
	{
		start_read();
		start_timer();
		trig_keep_alive(boost::posix_time::seconds(1));
	}

	const std::array<char, 3> keepstr = { 1, 2, 3 };

	void trig_keep_alive(const boost::posix_time::time_duration &tim)
	{
		auto self(shared_from_this());

		m_keep_timer.cancel();
		m_keep_timer.expires_from_now(tim);
		m_keep_timer.async_wait([this, self](boost::system::error_code ec) {
			if (!ec) {
				BOOST_LOG_TRIVIAL(info) << boost::format("send keep-a-live");
				write_data(keepstr.data(), keepstr.size());
			}
		});
	}

	virtual ~DTLS_Context()
	{
		BOOST_LOG_TRIVIAL(info) << boost::format("exit dtls");
	}

	void write_data(const char *dat, int length)
	{
		auto sndbuf = std::make_shared<std::vector<char> >(length);
		std::copy(dat, dat + length, sndbuf->begin());

		auto nullact = [this, sndbuf](boost::system::error_code ec, std::size_t length) {
		};

		m_socket->async_send(boost::asio::buffer(*sndbuf), boost::asio::bind_executor(m_strand, nullact));
		trig_keep_alive(boost::posix_time::seconds(1));
	}

	virtual void read_data_cb(char *buff, int length)
	{
		if (length == keepstr.size()) {
			auto chk = [&]() {
				for (int i = 0; i < keepstr.size(); i++) {
					if (buff[i] != keepstr[i]) {
						return false;
					}
				}
				return true;
			};

			if (chk() == true) {
				BOOST_LOG_TRIVIAL(info) << boost::format("get keep-a-live");
				return;
			}
		}

		char *printbuff = (char *)::alloca(length * 4);

		int prilen = 0;

		for (int i = 0; i < length; i++) {
			prilen += sprintf(printbuff + prilen, "%02X ", buff[i]);
		}
		BOOST_LOG_TRIVIAL(info) << boost::format("get len = %d,%s") % length % printbuff;
	}

	void shutdown()
	{
		if (shutdown_flg == 0) {
			if (exit_cb) {
				exit_cb();
			}
			BOOST_LOG_TRIVIAL(info) << boost::format("begin shutdown");
			m_keep_timer.cancel();

			shutdown_flg = 1;
			auto self(shared_from_this());
			auto shutcb = [this, self](boost::system::error_code ec) {
				m_close_timer.cancel();
				BOOST_LOG_TRIVIAL(info) << boost::format("shutdonw callback!!!");
			};

			m_socket->async_shutdown(boost::asio::bind_executor(m_strand, shutcb));

			//设定强制关闭
			m_close_timer.expires_from_now(boost::posix_time::seconds(5));
			auto timercb = [this, self](boost::system::error_code ec) {
				if (!ec) {
					BOOST_LOG_TRIVIAL(info) << boost::format("force shutdown");
					m_socket->next_layer().close();
				}
			};
			m_close_timer.async_wait(boost::asio::bind_executor(m_strand, timercb));

			m_recv_timer.cancel();
		}
	}

	void start_timer()
	{
		m_recv_timer.expires_from_now(boost::posix_time::seconds(5));
		auto self(shared_from_this());
		auto timercb = [this, self](boost::system::error_code ec) {
			if (!ec) {
				BOOST_LOG_TRIVIAL(info) << boost::format("recv timeout");
				shutdown();
			}
		};

		m_recv_timer.async_wait(boost::asio::bind_executor(m_strand, timercb));
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
	boost::asio::strand<boost::asio::io_context::executor_type> m_strand;
	boost::asio::deadline_timer m_recv_timer;
	boost::asio::deadline_timer m_close_timer;
	boost::asio::deadline_timer m_keep_timer;
	int shutdown_flg = 0;
};

#endif
