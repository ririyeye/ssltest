#ifndef __MBED_CFG_H__
#define __MBED_CFG_H__

#include <mbedtls/ssl.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <memory>


struct mbed_context {
	mbed_context()
	{
		mbedtls_ssl_config_init(&conf);
		mbedtls_x509_crt_init(&cacert);
		mbedtls_ctr_drbg_init(&ctr_drbg);
		mbedtls_entropy_init(&entropy);
		mbedtls_pk_init(&pkey);
	}

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;
	mbedtls_pk_context pkey;

	~mbed_context()
	{
		mbedtls_x509_crt_free(&cacert);
		mbedtls_ssl_config_free(&conf);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		mbedtls_pk_free(&pkey);
	}
};


std::unique_ptr<mbed_context> create_mbed_config_client(const char * CAfile);
std::unique_ptr<mbed_context> create_mbed_config_server(const char * x509file, const char *pkeyfile,const char * passwd);


#endif
