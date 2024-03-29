
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int create_socket(int port)
{
	int s;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Unable to bind");
		exit(EXIT_FAILURE);
	}

	if (listen(s, 1) < 0) {
		perror("Unable to listen");
		exit(EXIT_FAILURE);
	}

	return s;
}

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = TLS_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

static int pass(char *buf, int size, int rwflag, void *userdata)
{
	char *pass = "12138";
	strncpy(buf, (char *)pass, size);
	buf[strlen(pass)] = '\0';
	return strlen(pass);
}


static int my_pref_list[] =
{
NID_sect571r1, /* sect571r1 (14) */
NID_sect571k1, /* sect571k1 (13) */
NID_secp521r1, /* secp521r1 (25) */
NID_sect409k1, /* sect409k1 (11) */
NID_sect409r1, /* sect409r1 (12) */
NID_secp384r1, /* secp384r1 (24) */
NID_sect283k1, /* sect283k1 (9) */
NID_sect283r1, /* sect283r1 (10) */
NID_secp256k1, /* secp256k1 (22) */
NID_X9_62_prime256v1, /* secp256r1 (23) */
NID_sect239k1, /* sect239k1 (8) */
NID_sect233k1, /* sect233k1 (6) */
NID_sect233r1, /* sect233r1 (7) */
NID_secp224k1, /* secp224k1 (20) */
NID_secp224r1, /* secp224r1 (21) */
};

void configure_context(SSL_CTX *ctx)
{
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	SSL_CTX_set_default_passwd_cb(ctx, pass);

	if (SSL_CTX_load_verify_locations(ctx, "ca/ca.cer", NULL) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx, "server/pri.ca", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "server/pri_key.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	//验证密钥与证书是否匹配
	if (SSL_CTX_check_private_key(ctx) < 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	SSL_CTX_set1_curves(ctx,my_pref_list,sizeof(my_pref_list)/sizeof(int));
}

int main(int argc, char **argv)
{
	int sock;
	SSL_CTX *ctx;

	SSL_library_init();

	OpenSSL_add_all_algorithms();

	SSL_load_error_strings();

	ctx = create_context();

	configure_context(ctx);

	sock = create_socket(10000);

	/* Handle connections */
	while (1) {
		struct sockaddr_in addr;
		unsigned int len = sizeof(addr);
		SSL *ssl;
		const char reply[] = "test\n";

		int client = accept(sock, (struct sockaddr *)&addr, &len);
		if (client < 0) {
			perror("Unable to accept");
			exit(EXIT_FAILURE);
		}

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);

		if (SSL_accept(ssl) <= 0) {
			ERR_print_errors_fp(stderr);
		} else {
			printf("sharkhand ok!\n");
			SSL_write(ssl, reply, strlen(reply));
		}

		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(client);
	}

	close(sock);
	SSL_CTX_free(ctx);
}