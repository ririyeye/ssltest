

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
void default_connect();
void ssl_read_cb(uv_ssl_context *ssl,
		 ssize_t nread,
		 const char *buff)
{
	printf("get buff = %ld,%s\n", nread, buff);

	if (!strncmp("close", buff, 5)) {
		uv_ssl_close(ssl);
	}
}

void close_cb(uv_handle_t *handle)
{
	uv_tcp_t *pclient = (uv_tcp_t *)handle;
	delete handle;
	default_connect();
}

void on_event(uv_ssl_context *pssl, int status)
{
	if (status == ssl_connected) {
		int ret = mbedtls_ssl_get_verify_result(&pssl->ssl);
		uv_ssl_close(pssl);
		printf("handshake ok \n");
		pssl->rd_cb = ssl_read_cb;
	} else if (status == ssl_closing) {
		uv_close((uv_handle_t *)pssl->phandle, close_cb);
	}
}

void connect_cb(uv_connect_t *req, int status)
{
	if (status < 0) {
		delete req->handle;
		delete req;
		default_connect();
		return;
	}
	uv_create_ssl(req->handle, (mbed_context *)req->data, on_event);
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

unique_ptr<mbed_context> conf;
uv_loop_t *loop = uv_default_loop();

void default_connect()
{
	create_connect(loop, "216.238.79.71", 8888, conf.get());
}

int main(void)
{
	signal(SIGPIPE, SIG_IGN);

	conf = create_mbed_config_client("ca/ca.cer");

	loop = uv_default_loop();

	for(int i = 0 ;i < 500;i++) {
		default_connect();
	}

	uv_run(loop, UV_RUN_DEFAULT);

	return 0;
}
