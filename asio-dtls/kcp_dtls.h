#ifndef __kcp_dtls_h__
#define __kcp_dtls_h__

#include "kcp/ikcp.h"
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/async_result.hpp>
#include <functional>
#include <iostream>
class kcp_context {
    public:
	explicit kcp_context(boost::asio::io_context &io_ctx)
		: m_strand(io_ctx.get_executor()), m_kcp_timer(io_ctx)
	{
		pkcp = ikcp_create(1, this);
		pkcp->mtu = 1350;
		trig_kcp_timer();
		pkcp->output = _output;
	}

	void async_write_kcp(const char *dat, int length, std::function<void(const char *buff, int len)> input_write_cb)
	{
		boost::asio::dispatch(m_strand, [this, dat, length, input_write_cb]() {
			int ret = ikcp_send(pkcp, dat, length);
			if (input_write_cb) {
				input_write_cb(dat, ret < 0 ? ret : length);
			}
		});
	}

	void async_read_kcp(char *buff, int len, std::function<void(const char *buff, int len)> input_read_cb)
	{
		async_read_cb_buff = buff;
		async_read_cb_len = len;
		async_read_cb = input_read_cb;

		boost::asio::dispatch(m_strand, [this]() {
			if (async_read_cb_buff && async_read_cb_len > 0 && async_read_cb) {
				int rdlen = ikcp_recv(pkcp, async_read_cb_buff, async_read_cb_len);
				if (rdlen > 0) {
					async_read_cb_len = -1;
					async_read_cb(async_read_cb_buff, rdlen);
				}
			}
		});
	}

	void async_input_kcp(const char *dat, int length, std::function<void(const char *buff, int len)> input_cb)
	{
		boost::asio::dispatch(m_strand, [this, dat, length, input_cb]() {
			ikcp_input(pkcp, dat, length);
			if (input_cb) {
				input_cb(dat, length);
			}

			if (async_read_cb_buff && async_read_cb_len > 0 && async_read_cb) {
				int rdlen = ikcp_recv(pkcp, async_read_cb_buff, async_read_cb_len);
				if (rdlen > 0) {
					async_read_cb_len = -1;
					async_read_cb(async_read_cb_buff, rdlen);
				}
			}
		});
	}

	void trig_kcp_timer()
	{
		m_kcp_timer.cancel();
		m_kcp_timer.expires_from_now(boost::posix_time::milliseconds(10));
		boost::asio::spawn(m_strand, [this](boost::asio::yield_context yie) {
			boost::system::error_code ec;
			do {
				timeval tv;
				gettimeofday(&tv, nullptr);
				uint64_t t64 = tv.tv_sec * 1000 + tv.tv_usec / 1000;
				ikcp_update(pkcp, t64);

				m_kcp_timer.expires_from_now(boost::posix_time::milliseconds(10));
				m_kcp_timer.async_wait(yie[ec]);

			} while (!ec);
		});
	}

	std::function<void(const char *buff, int len)> output_cb;

	~kcp_context()
	{
		m_kcp_timer.cancel();
		if (pkcp) {
			ikcp_release(pkcp);
		}
	}

    private:
	std::function<void(const char *buff, int len)> async_read_cb;
	char *async_read_cb_buff = 0;
	int async_read_cb_len = 0;

	static int _output(const char *buf, int len, struct IKCPCB *kcp, void *user)
	{
		kcp_context *pctx = (kcp_context *)user;
		return pctx->output(buf, len);
	}

	int output(const char *buf, int len)
	{
		if (output_cb) {
			output_cb(buf, len);
			return len;
		}
		return -1;
	}

	ikcpcb *pkcp = nullptr;
	boost::asio::strand<boost::asio::io_context::executor_type> m_strand;
	boost::asio::deadline_timer m_kcp_timer;
};

#endif
