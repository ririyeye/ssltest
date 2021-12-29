



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

int main(void)
{

	auto conf = dtls_main();


	return 0;
}
