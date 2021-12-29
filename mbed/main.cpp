

#include "mbedtls/config.h"

#include "mbedtls/platform.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include <string.h>
#include <memory>
#include "mbed_uv.h"

using namespace std;

unique_ptr<mbed_context> dtls_main(void);
int create_connect(uv_loop_t *loop, const char *ip, int port, mbed_context *ctx);

int main(void)
{
	auto conf = dtls_main();

	uv_loop_t *loop = uv_default_loop();

	create_connect(loop, "127.0.0.1", 8888, conf.get());

	uv_run(loop, UV_RUN_DEFAULT);

	return 0;
}
