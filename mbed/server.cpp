

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
#include <time.h>
using namespace std;

struct connect_data : public uv_timer_t {
	int readtim = 0;
	uv_ssl_context *pssl;
};

void on_timer_close_cb(uv_handle_t *handle)
{
	uv_tcp_t *pclient = (uv_tcp_t *)handle;
	delete handle;
}

void on_timer_cb(uv_timer_t *handle)
{
	connect_data *ptim = (connect_data *)handle;

	if (ptim->pssl) {
		char buff[128];
		time_t current_tim;
		time(&current_tim);
		tm tmp_tm;
		localtime_r(&current_tim, &tmp_tm);
		int len = sprintf(buff, "timer write = %d,", ptim->readtim++);
		len += strftime(buff + len, 128 - len, "%x %X", &tmp_tm);
		len += sprintf(buff + len, "\n");

		uv_ssl_write(ptim->pssl, len, buff);
	} else {
		uv_unref((uv_handle_t *)ptim);
		uv_close((uv_handle_t *)ptim, on_timer_close_cb);
	}
}

void ssl_read_cb(uv_ssl_context *ssl,
		 ssize_t nread,
		 const char *buff)
{
	if (ssl->data) {
		connect_data *ptimer = (connect_data *)ssl->data;
		uv_timer_again(ptimer);
	}

	printf("get buff = %ld,%s\n", nread, buff);

	uv_ssl_write(ssl, nread, buff);

	if (!strncmp("close", buff, 5)) {
		uv_ssl_close(ssl);
	}
}

void error_close_cb(uv_handle_t *handle)
{
	uv_tcp_t *pclient = (uv_tcp_t *)handle;
	delete handle;
}

void on_event(uv_ssl_context *pssl, int status)
{
	if (status == ssl_connected) {
		printf("handshake ok \n");
		pssl->rd_cb = ssl_read_cb;

		connect_data *pdat = new connect_data();
		uv_timer_init(pssl->phandle->loop, pdat);
		uv_timer_start(pdat, on_timer_cb, 2000, 2000);

		pssl->data = pdat;
		pdat->pssl = pssl;
	} else if (status == ssl_closing) {
		if (pssl->data) {
			connect_data *ptimer = (connect_data *)pssl->data;
			ptimer->pssl = nullptr;
			uv_unref((uv_handle_t *)ptimer);
			uv_close((uv_handle_t *)ptimer, on_timer_close_cb);
		}
		uv_close((uv_handle_t *)pssl->phandle, error_close_cb);
	}
}

void on_connection_cb(uv_stream_t *server, int status)
{
	if (status < 0) {
		return;
	}

	uv_tcp_t *pclient = new uv_tcp_t();
	uv_tcp_init(server->loop, pclient);
	if (uv_accept(server, (uv_stream_t *)pclient) == 0) {
		uv_create_ssl((uv_stream_t *)pclient, (mbed_context *)server->data, on_event);
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
