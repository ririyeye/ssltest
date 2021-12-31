

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
#define DEBUG_LEVEL 0

static void my_debug(void *ctx, int level,
		     const char *file, int line,
		     const char *str)
{
	((void)level);

	mbedtls_fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
	fflush((FILE *)ctx);
}

unique_ptr<mbed_context> create_mbed_config_client(const char *CAfile)
{
	int ret = 1, len;
	int exit_code = MBEDTLS_EXIT_FAILURE;
	const char *pers = "ssl_client1";

	unique_ptr<mbed_context> pmc = make_unique<mbed_context>();

	mbedtls_debug_set_threshold(DEBUG_LEVEL);

	if ((ret = mbedtls_ctr_drbg_seed(&pmc->ctr_drbg, mbedtls_entropy_func, &pmc->entropy,
					 (const unsigned char *)pers,
					 strlen(pers))) != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
		return nullptr;
	}

	ret = mbedtls_x509_crt_parse_file(&pmc->cacert, CAfile);

	if (ret < 0) {
		mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
		return nullptr;
	}

	if ((ret = mbedtls_ssl_config_defaults(&pmc->conf,
					       MBEDTLS_SSL_IS_CLIENT,
					       MBEDTLS_SSL_TRANSPORT_STREAM,
					       MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
		return nullptr;
	}

	/* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
	mbedtls_ssl_conf_authmode(&pmc->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&pmc->conf, &pmc->cacert, NULL);
	mbedtls_ssl_conf_rng(&pmc->conf, mbedtls_ctr_drbg_random, &pmc->ctr_drbg);
	mbedtls_ssl_conf_dbg(&pmc->conf, my_debug, stdout);

	return pmc;
}

std::unique_ptr<mbed_context> create_mbed_config_server(const char * x509file, const char *pkeyfile,const char * passwd)
{
	int ret = 1, len;
	int exit_code = MBEDTLS_EXIT_FAILURE;
	const char *pers = "ssl_client1";

	unique_ptr<mbed_context> pmc = make_unique<mbed_context>();

	mbedtls_debug_set_threshold(DEBUG_LEVEL);

	if ((ret = mbedtls_ctr_drbg_seed(&pmc->ctr_drbg, mbedtls_entropy_func, &pmc->entropy,
					 (const unsigned char *)pers,
					 strlen(pers))) != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
		return nullptr;
	}

	ret = mbedtls_x509_crt_parse_file(&pmc->cacert, x509file);

	if (ret < 0) {
		mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
		return nullptr;
	}

	ret = mbedtls_pk_parse_keyfile(&pmc->pkey, pkeyfile, passwd);
	if (ret != 0) {
		mbedtls_printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
		return nullptr;
	}

	if ((ret = mbedtls_ssl_config_defaults(&pmc->conf,
					       MBEDTLS_SSL_IS_SERVER,
					       MBEDTLS_SSL_TRANSPORT_STREAM,
					       MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
		return nullptr;
	}

	if ((ret = mbedtls_ssl_conf_own_cert(&pmc->conf, &pmc->cacert, &pmc->pkey)) != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
		return nullptr;
	}

	/* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
	//mbedtls_ssl_conf_authmode(&pmc->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&pmc->conf, &pmc->cacert, NULL);
	mbedtls_ssl_conf_rng(&pmc->conf, mbedtls_ctr_drbg_random, &pmc->ctr_drbg);
	mbedtls_ssl_conf_dbg(&pmc->conf, my_debug, stdout);

	return pmc;
}
