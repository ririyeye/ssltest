

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <iostream>
#include "mbed_cfg.h"
#include <memory>

#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include "mbed_cfg.h"
#include <list>
#include <vector>

using boost::asio::ip::tcp;

class session
	: public std::enable_shared_from_this<session> {
    public:
	session(tcp::socket socket, boost::asio::io_context &ctx, mbed_context *pctx)
		: m_strand(ctx), socket_(std::move(socket)), mbed_ctx(pctx)
	{
	}
	~session()
	{
	}
	void start()
	{
		mbedtls_ssl_init(&ctx);
		int ret;
		if ((ret = mbedtls_ssl_setup(&ctx, &mbed_ctx->conf)) != 0) {
			return;
		}
		sta = ssl_handshake;

		mbedtls_ssl_set_bio(&ctx, this, mbedtls_ssl_send_bio, mbedtls_ssl_recv_bio, nullptr);

		start_read();
		handshake();
	}

	void write_dat(const char *buff, int len)
	{
		if (sta == ssl_connected) {
			auto snd = std::make_shared<std::vector<char> >(len);
			std::copy(buff, buff + len, snd->begin());
			auto self(shared_from_this());
			m_strand.post([this, snd, self]() {
				mbedtls_ssl_write(&ctx, (unsigned char *)&snd->at(0), snd->size());
			});
		}
	}

    private:
	static int mbedtls_ssl_send_bio(void *ctx,
					const unsigned char *buf,
					size_t len)
	{
		session *psession = (session *)ctx;

		return psession->mbedtls_ssl_send_bio(buf, len);
	}

	int mbedtls_ssl_send_bio(const unsigned char *buf, size_t len)
	{
		boost::system::error_code ec;
		int ret = socket_.write_some(boost::asio::buffer(buf, len), ec);
		if (!ec) {
			return ret;
		}
		printf("write error = %s\n", ec.message().c_str());
		return ec.value();
	}

	static int mbedtls_ssl_recv_bio(void *ctx,
					unsigned char *buf,
					size_t len)
	{
		session *psession = (session *)ctx;

		return psession->mbedtls_ssl_recv_bio(buf, len);
	}

	int mbedtls_ssl_recv_bio(
		unsigned char *buf,
		size_t len)
	{
		if (!rcv_bio_list.empty()) {
			auto itr = rcv_bio_list.begin();
			if (len >= itr->datelen - itr->startpos) {
				len = itr->datelen - itr->startpos;
				memcpy(buf, itr->buff + itr->startpos, itr->datelen - itr->startpos);
				rcv_bio_list.pop_front();
				return len;
			} else {
				memcpy(buf, itr->buff + itr->startpos, len);
				itr->startpos += len;
				return len;
			}
		}
		return 0;
	}

	struct rcv_buffs {
		char buff[2048];
		int startpos;
		int datelen;
		int bufflen;
	};

	void handshake()
	{
		int ret = mbedtls_ssl_handshake(&ctx);
		if (ret == 0) {
			sta = ssl_connected;
		}
	}

	void on_read(boost::system::error_code ec, std::size_t length, std::shared_ptr<session> self)
	{
		if (!ec) {
			rcv_buffs bufs;
			memcpy(bufs.buff, data_, length);
			bufs.bufflen = 2048;
			bufs.datelen = length;
			bufs.startpos = 0;

			rcv_bio_list.emplace_back(bufs);

			if (sta == ssl_handshake) {
				handshake();
			} else if (sta == ssl_closing) {
				return;
			} else {
				unsigned char tmpbuff[4096];
				int len;
				while (true) {
					len = mbedtls_ssl_read(&ctx, tmpbuff, 4096);
					if (len > 0) {
						write_dat((char *)tmpbuff, len);
						//printf("get dat = %s\n", tmpbuff);
					} else if (len == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
						return;
						break;
					} else {
						break;
					}
				}
			}
			start_read();
		}
	}

	void start_read()
	{
		auto self(shared_from_this());

		auto _onrd = boost::bind(&session::on_read, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred, self);

		socket_.async_read_some(boost::asio::buffer(data_, max_length), boost::asio::bind_executor(m_strand, _onrd));
	}

	enum mbed_stat {
		ssl_none = 0,
		ssl_handshake,
		ssl_connected,
		ssl_closing,
		ssl_base_broken_pip,
	};

	tcp::socket socket_;
	boost::asio::io_context::strand m_strand;
	mbed_context *mbed_ctx;
	mbedtls_ssl_context ctx;
	std::list<rcv_buffs> rcv_bio_list;
	mbed_stat sta = ssl_none;
	enum { max_length = 2048 };
	char data_[max_length];
};
