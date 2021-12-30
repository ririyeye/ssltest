

#include "mbedtls/config.h"

#include "mbedtls/platform.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include <string.h>
#include <memory>
#include "mbed_uv.h"
#include "mbed_cfg.h"
using namespace std;

void ssl_read_cb(uv_ssl_context *ssl,
		 ssize_t nread,
		 const char *buff)
{
	printf("get buff = %ld,%s\n", nread, buff);

	uv_ssl_write(ssl, nread, buff);

	if (!strncmp("close", buff, 5)) {
		uv_ssl_close(ssl);
	}
}

void on_handshake(uv_ssl_context *pssl, int status)
{
	if (status == 0) {
		printf("handshake ok \n");
		pssl->rd_cb = ssl_read_cb;
		pssl->close_cb = [](uv_ssl_context* pssl) {
			delete (uv_tcp_t*)pssl->phandle;
		};
	}
}

void error_close_cb(uv_handle_t *handle)
{
	uv_tcp_t *pclient = (uv_tcp_t *)handle;
	delete handle;
}

void on_connection_cb(uv_stream_t *server, int status)
{
	if (status < 0) {
		return;
	}

	uv_tcp_t *pclient = new uv_tcp_t();
	uv_tcp_init(server->loop, pclient);
	if (uv_accept(server, (uv_stream_t *)pclient) == 0) {
		uv_create_ssl((uv_stream_t*)pclient, (mbed_context *)server->data, on_handshake);
	} else {
		uv_close((uv_handle_t *)pclient, error_close_cb);
	}
}

int create_bind(uv_loop_t *loop, int port, mbed_context *ctx)
{
	uv_tcp_t *ptcp = new uv_tcp_t();
	uv_tcp_init(loop, ptcp);
	ptcp->data = ctx;

	sockaddr_in server_addr;
	uv_ip4_addr("0.0.0.0", port, &server_addr);

	uv_tcp_bind(ptcp, (sockaddr *)&server_addr, 0);

	uv_listen((uv_stream_t *)ptcp, 128, on_connection_cb);

	return 0;
}

int main(void)
{
	auto conf = create_mbed_config_server("server/pri.ca", "server/pri_key.pem", "12138");

	uv_loop_t *loop = uv_default_loop();

	create_bind(loop, 8888, conf.get());

	uv_run(loop, UV_RUN_DEFAULT);

	return 0;
}
