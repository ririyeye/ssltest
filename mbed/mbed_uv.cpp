
#include "mbed_uv.h"
#include "string.h"
#include <memory>

struct write_req_t : public uv_write_t {
	write_req_t(const void *src, int len)
		: dat(new char[len])
	{
		memcpy(dat.get(), src, len);
		buf = uv_buf_init(dat.get(), len);
	}
	uv_buf_t buf;
	std::unique_ptr<char[]> dat;
};

void uv_write_cb0(uv_write_t *req, int status)
{
	delete (write_req_t *)req;
}

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
	(void)handle;
	const int bufflen = suggested_size;
	buf->base = new char[bufflen];
	buf->len = bufflen;
}

void uv_close_cb_mbed(uv_handle_t *handle)
{
	uv_tcp_t *stream = (uv_tcp_t *)handle;

	uv_ssl_context *ctx = (uv_ssl_context *)stream->data;

	mbedtls_ssl_free(&ctx->ssl);

	delete ctx;

	delete stream;
}

void uv_ssl_close(uv_ssl_context *ssl)
{
	ssl->sta = ssh_closing;
	int ret = mbedtls_ssl_close_notify(&ssl->ssl);
	if (ret == 0) {
		uv_close((uv_handle_t *)ssl->phandle, uv_close_cb_mbed);
	}
}

void uv_read_cb_bio(uv_stream_t *stream,
		    ssize_t nread,
		    const uv_buf_t *buf)
{
	uv_ssl_context *ctx = (uv_ssl_context *)stream->data;
	if (nread > 0) {
		rcv_buf tmp;
		tmp.buff = buf->base;
		tmp.bufflen = buf->len;
		tmp.datelen = nread;
		tmp.startpos = 0;
		ctx->rcv_bio_list.emplace_back(tmp);

		if (ctx->sta == ssl_handshake) {
			int ret = mbedtls_ssl_handshake(&ctx->ssl);
			if (ret == 0) {
				ctx->sta = ssl_handshake_ok;
			}
		} else if (ctx->sta == ssh_closing) {
			int ret = mbedtls_ssl_close_notify(&ctx->ssl);
			if (ret == 0) {
				uv_close((uv_handle_t *)stream, uv_close_cb_mbed);
			}
		} else {
			unsigned char tmpbuff[4096];
			int len;
			while (true) {
				len = mbedtls_ssl_read(&ctx->ssl, tmpbuff, 4096);
				if (len > 0) {
					if (ctx->rd_cb) {
						ctx->rd_cb(ctx, len, (char *)tmpbuff);
					}
				} else if (len == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
					int ret = mbedtls_ssl_close_notify(&ctx->ssl);
					if (ret == 0) {
						uv_close((uv_handle_t *)ctx->phandle, uv_close_cb_mbed);
					}
					break;
				} else {
					break;
				}
			}
		}
	} else if (nread == 0) {
		printf("read = 0\n");
	} else {
		if (buf && buf->base) {
			delete[] buf->base;
		}
		if (ctx->sta == ssl_handshake_ok) {
			ctx->sta = ssh_closing;
			int ret = mbedtls_ssl_close_notify(&ctx->ssl);
			if (ret == 0) {
				uv_close((uv_handle_t *)stream, uv_close_cb_mbed);
			}
		}
	}
}

int mbedtls_ssl_send_bio(void *ctx,
			 const unsigned char *buf,
			 size_t len)
{
	uv_stream_t *pio = (uv_stream_t *)ctx;

	write_req_t *wreq = new write_req_t(buf, len);

	uv_write(wreq, pio, &wreq->buf, 1, uv_write_cb0);
	return len;
}

int mbedtls_ssl_recv_bio(void *ctx,
			 unsigned char *buf,
			 size_t len)
{
	uv_stream_t *pio = (uv_stream_t *)ctx;
	uv_ssl_context *usr_ctx = (uv_ssl_context *)pio->data;

	if (!usr_ctx->rcv_bio_list.empty()) {
		auto itr = usr_ctx->rcv_bio_list.begin();
		if (len >= itr->datelen - itr->startpos) {
			len = itr->datelen - itr->startpos;
			memcpy(buf, itr->buff + itr->startpos, itr->datelen - itr->startpos);
			delete[] itr->buff;
			usr_ctx->rcv_bio_list.pop_front();
			return len;
		} else {
			memcpy(buf, itr->buff + itr->startpos, len);
			itr->startpos += len;
			return len;
		}
	}
	return 0;
}

// typedef void (*uv_ssl_read_cb)(uv_ssl_context *ssl,
// 			       ssize_t nread,
// 			       const char *buff);

// void uv_ssl_close(uv_ssl_context *ssl);

void ssl_read_cb(uv_ssl_context *ssl,
		 ssize_t nread,
		 const char *buff)
{
	printf("get buff = %ld,%s\n", nread, buff);

	if (!strncmp("close", buff, 5)) {
		uv_ssl_close(ssl);
	}
}

void connect_cb(uv_connect_t *req, int status)
{
	if (status < 0) {
		delete req->handle;
		delete req;
		return;
	}

	uv_ssl_context *ssl = new uv_ssl_context();
	ssl->ctx = (mbed_context *)req->data;

	req->handle->data = ssl;

	mbedtls_ssl_init(&ssl->ssl);

	int ret;

	if ((ret = mbedtls_ssl_setup(&ssl->ssl, &ssl->ctx->conf)) != 0) {
		return;
	}

#if 0
//不要去验证,mbedtls统配有问题 只能添加固定host
	if ((ret = mbedtls_ssl_set_hostname(&ssl, "server.kvm")) != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
		goto exit;
	}
#endif
	ssl->phandle = req->handle;
	ssl->sta = ssl_handshake;
	ssl->rd_cb = ssl_read_cb;
	uv_read_start(req->handle, alloc_buffer, uv_read_cb_bio);
	mbedtls_ssl_set_bio(&ssl->ssl, req->handle, mbedtls_ssl_send_bio, mbedtls_ssl_recv_bio, nullptr);

	ret = mbedtls_ssl_handshake(&ssl->ssl);
	if (ret == 0) {
		ssl->sta = ssl_handshake_ok;
	}

	delete req;
}

int create_connect(uv_loop_t *loop, const char *ip, int port, mbed_context *ctx)
{
	sockaddr_in server_addr;
	uv_ip4_addr(ip, port, &server_addr);

	uv_connect_t *connect = new uv_connect_t();

	uv_tcp_t *ptcp = new uv_tcp_t();
	uv_tcp_init(loop, ptcp);

	connect->data = ctx;

	uv_tcp_connect(connect, ptcp, (sockaddr *)&server_addr, connect_cb);

	return 0;
}
