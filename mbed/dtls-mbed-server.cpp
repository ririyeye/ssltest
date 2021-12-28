


#include "mbedtls/config.h"

#include "mbedtls/platform.h"


#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include <mbedtls/ssl.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include <string.h>


#define DEBUG_LEVEL 2

static void my_debug(void *ctx, int level,
		     const char *file, int line,
		     const char *str)
{
	((void)level);

	mbedtls_fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
	fflush((FILE *)ctx);
}

int main(void)
{
	int ret = 1, len;
	int exit_code = MBEDTLS_EXIT_FAILURE;
	mbedtls_net_context server_fd;
	uint32_t flags;
	unsigned char buf[1024];
	const char *pers = "ssl_client1";

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;

#if defined(MBEDTLS_DEBUG_C)
	mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

	/*
     * 0. Initialize the RNG and the session data
     */
	mbedtls_net_init(&server_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&cacert);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_printf("\n  . Seeding the random number generator...");
	fflush(stdout);

	mbedtls_entropy_init(&entropy);
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
					 (const unsigned char *)pers,
					 strlen(pers))) != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	/*
     * 0. Initialize certificates
     */
	mbedtls_printf("  . Loading the CA root certificate ...");
	fflush(stdout);
#if 0
	ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)mbedtls_test_cas_pem,
				     mbedtls_test_cas_pem_len);
	if (ret < 0) {
		mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
		goto exit;
	}
#else
	ret = mbedtls_x509_crt_parse_file(&cacert, "/ca.cer");

	if (ret < 0) {
		mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
		goto exit;
	}
#endif
	mbedtls_printf(" ok (%d skipped)\n", ret);

	/*
     * 1. Start the connection
     */
#if 0
	if ((ret = mbedtls_net_connect(&server_fd, SERVER_NAME,
				       SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
		goto exit;
	}
#endif
	mbedtls_printf(" ok\n");

	/*
     * 2. Setup stuff
     */
	mbedtls_printf("  . Setting up the SSL/TLS structure...");
	fflush(stdout);

	if ((ret = mbedtls_ssl_config_defaults(&conf,
					       MBEDTLS_SSL_IS_CLIENT,
					       MBEDTLS_SSL_TRANSPORT_STREAM,
					       MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	/* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
		goto exit;
	}
	//不要去验证,mbedtls统配有问题 只能添加固定host
#if 0
	if ((ret = mbedtls_ssl_set_hostname(&ssl, "server.kvm")) != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
		goto exit;
	}
#endif
	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

	/*
     * 4. Handshake
     */
	mbedtls_printf("  . Performing the SSL/TLS handshake...");
	fflush(stdout);

	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
			goto exit;
		}
	}

	mbedtls_printf(" ok\n");

	/*
     * 5. Verify the server certificate
     */
	mbedtls_printf("  . Verifying peer X.509 certificate...");

	/* In real life, we probably want to bail out when ret != 0 */
	if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
		char vrfy_buf[512];

		mbedtls_printf(" failed\n");

		mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

		mbedtls_printf("%s\n", vrfy_buf);
	} else
		mbedtls_printf(" ok\n");


	len = ret;
	mbedtls_printf(" %d bytes written\n\n%s", len, (char *)buf);

	/*
     * 7. Read the HTTP response
     */
	mbedtls_printf("  < Read from server:");
	fflush(stdout);

	do {
		len = sizeof(buf) - 1;
		memset(buf, 0, sizeof(buf));
		ret = mbedtls_ssl_read(&ssl, buf, len);

		if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
			continue;

		if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
			break;

		if (ret < 0) {
			mbedtls_printf("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret);
			break;
		}

		if (ret == 0) {
			mbedtls_printf("\n\nEOF\n\n");
			break;
		}

		len = ret;
		mbedtls_printf(" %d bytes read\n\n%s", len, (char *)buf);
	} while (1);

	mbedtls_ssl_close_notify(&ssl);

	exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

	if (exit_code != MBEDTLS_EXIT_SUCCESS) {
		char error_buf[100];
		mbedtls_strerror(ret, error_buf, 100);
		mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
	}


	mbedtls_net_free(&server_fd);

	mbedtls_x509_crt_free(&cacert);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	mbedtls_exit(exit_code);
}
