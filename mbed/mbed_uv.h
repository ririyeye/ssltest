#ifndef __MBED_UV_H__
#define __MBED_UV_H__

#include <uv.h>
#include <mbedtls/ssl.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <list>
#include "mbed_cfg.h"

struct rcv_buf {
	char *buff;
	int startpos;
	int datelen;
	int bufflen;
};

enum ssl_stat {
	ssl_none = 0,
	ssl_handshake,
	ssl_connected,
	ssl_closing,
};

struct uv_ssl_context;
typedef void (*uv_ssl_read_cb)(uv_ssl_context *pssl,
			       ssize_t nread,
			       const char *buff);

int uv_ssl_write(uv_ssl_context *pssl,
		 ssize_t nread,
		 const char *buff);

typedef void (*uv_ssl_handshake_cb)(uv_ssl_context *pssl,
				    int status);

void uv_ssl_close(uv_ssl_context *pssl);
int uv_create_ssl(uv_stream_t *phandle, mbed_context *pctx, uv_ssl_handshake_cb connect_cb);

struct uv_ssl_context {
	mbedtls_ssl_context ssl;
	ssl_stat sta = ssl_none;
	mbed_context *pconf;
	std::list<rcv_buf> rcv_bio_list;
	uv_ssl_read_cb rd_cb = nullptr;
	uv_ssl_handshake_cb handshake_cb = nullptr;
	uv_stream_t *phandle;
};

#endif
