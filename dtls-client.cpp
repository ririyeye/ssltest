
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

union PEER {
	struct sockaddr_storage ss;
	struct sockaddr_in s4;
	struct sockaddr_in6 s6;
};

int create_socket(PEER &addr, char *serverip, int port, BIO **bio)
{
	int s;

	addr.s4.sin_family = AF_INET;
	addr.s4.sin_port = htons(port);
	addr.s4.sin_addr.s_addr = inet_addr(serverip);

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}

	*bio = BIO_new_dgram(s, BIO_CLOSE);

	if (connect(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}

	BIO_ctrl(*bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &addr.ss);

	return s;
}

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = DTLS_client_method();

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

static int pass(char *buf, int size, int rwflag, void *userdata)
{
	char *pass = "12138";
	strncpy(buf, (char *)pass, size);
	buf[strlen(pass)] = '\0';
	return strlen(pass);
}

void configure_context(SSL_CTX *ctx)
{
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	SSL_CTX_set_default_passwd_cb(ctx, pass);

	SSL_CTX_load_verify_locations(ctx, "ca/ca.cer", NULL);

	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx, "client/pri.ca", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "client/pri_key.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	//验证密钥与证书是否匹配
	if (SSL_CTX_check_private_key(ctx) < 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	SSL_CTX_set1_curves(ctx, my_pref_list, sizeof(my_pref_list) / sizeof(int));
}

int main(int argc, char **argv)
{
	int verbose = 1;
	int veryverbose = 1;
	SSL_CTX *ctx;

	SSL_library_init();

	OpenSSL_add_all_algorithms();

	SSL_load_error_strings();

	ctx = create_context();

	configure_context(ctx);

	PEER server;
	/* Handle connections */
	BIO *bio;
	while (1) {
		SSL *ssl = SSL_new(ctx);

		int sock = create_socket(server, "127.0.0.1", 20000, &bio);

		SSL_set_bio(ssl, bio, bio);

		int retval = SSL_connect(ssl);

		if (retval <= 0) {
			switch (SSL_get_error(ssl, retval)) {
			case SSL_ERROR_ZERO_RETURN:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_ZERO_RETURN\n");
				break;
			case SSL_ERROR_WANT_READ:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_READ\n");
				break;
			case SSL_ERROR_WANT_WRITE:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_WRITE\n");
				break;
			case SSL_ERROR_WANT_CONNECT:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_CONNECT\n");
				break;
			case SSL_ERROR_WANT_ACCEPT:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_ACCEPT\n");
				break;
			case SSL_ERROR_WANT_X509_LOOKUP:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_X509_LOOKUP\n");
				break;
			case SSL_ERROR_SYSCALL:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_SYSCALL\n");
				break;
			case SSL_ERROR_SSL:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_SSL\n");
				break;
			default:
				fprintf(stderr, "SSL_connect failed with unknown error\n");
				break;
			}
			exit(EXIT_FAILURE);
		}

		/* Set and activate timeouts */
		timeval timeout;
		timeout.tv_sec = 3;
		timeout.tv_usec = 0;
		BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

		if (verbose) {
			char addrbuf[1024];
			printf("Connected to %s\n",
			       inet_ntop(AF_INET, &server.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN));
		}

		if (veryverbose && SSL_get_peer_certificate(ssl)) {
			printf("------------------------------------------------------------\n");
			X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)),
					      1, XN_FLAG_MULTILINE);
			printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
			printf("\n------------------------------------------------------------\n\n");
		}

		unsigned char buff[1024];
		while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)) {
			SSL_write(ssl, "123\n", 4);
			unsigned char buff[1024];

			int len = SSL_read(ssl, buff, 1024);

			printf("get %d:%s\n", len, buff);
			sleep(1);
		}
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(sock);
	}
	SSL_CTX_free(ctx);
}