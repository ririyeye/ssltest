
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int create_socket(char *serverip, int port)
{
	int s;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(serverip);

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}

	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}
	return s;
}

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = TLSv1_2_client_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

static int my_pref_list[] = {
	NID_secp256k1, /* secp256k1 (22) */
};

void configure_context(SSL_CTX *ctx)
{
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	SSL_CTX_load_verify_locations(ctx, "ca/ca.cer", NULL);

	SSL_CTX_set1_curves(ctx, my_pref_list, sizeof(my_pref_list) / sizeof(int));
}

int main(int argc, char **argv)
{
	SSL_CTX *ctx;

	SSL_library_init();

	OpenSSL_add_all_algorithms();

	SSL_load_error_strings();

	ctx = create_context();

	configure_context(ctx);

	/* Handle connections */
	while (1) {
		int sock = create_socket("139.180.178.5", 10000);

		SSL *ssl = SSL_new(ctx);

		SSL_set_fd(ssl, sock);

		if (0 > SSL_connect(ssl)) {
			ERR_print_errors_fp(stderr);
		} else {
			printf("SSL connection using %s\n", SSL_get_cipher(ssl));
		}

		unsigned char buff[1024];
		int len = SSL_read(ssl, buff, 1024);

		printf("get %d:%s\n", len, buff);
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(sock);
	}
	SSL_CTX_free(ctx);
}