#ifndef __MBED_UV_H__
#define __MBED_UV_H__

#include <uv.h>
#include <mbedtls/ssl.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <list>
struct mbed_context {
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;

	~mbed_context()
	{
		mbedtls_x509_crt_free(&cacert);
		mbedtls_ssl_config_free(&conf);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
	}
};

struct rcv_buf {
	char *buff;
	int startpos;
	int datelen;
	int bufflen;
};

enum ssl_stat {
	ssl_none = 0,
	ssl_handshake,
	ssl_handshake_ok,
	ssh_closing,
};


struct uv_ssl_context;
typedef void (*uv_ssl_read_cb)(uv_ssl_context *stream,
			   ssize_t nread,
			   const char * buff);

struct uv_ssl_context {
	mbedtls_ssl_context ssl;
	ssl_stat sta = ssl_none;
	mbed_context *ctx;
	std::list<rcv_buf> rcv_bio_list;
	uv_ssl_read_cb rd_cb = nullptr;
};

#endif

