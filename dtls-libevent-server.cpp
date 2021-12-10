
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <memory>
#include <thread>

#include <event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>

event_base *evbase = NULL;

using namespace std;
union PEER {
	struct sockaddr_storage ss;
	struct sockaddr_in6 s6;
	struct sockaddr_in s4;
};
struct pass_info {
	PEER server_addr;
	PEER client_addr;
	SSL *ssl;
};

int create_socket(PEER &peer, int port)
{
	int s;
	const int on = 1, off = 0;

	peer.s4.sin_family = AF_INET;
	peer.s4.sin_port = htons(port);
	peer.s4.sin_addr.s_addr = htonl(INADDR_ANY);

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}

	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, (socklen_t)sizeof(on));

	if (bind(s, (struct sockaddr *)&peer, sizeof(sockaddr_in)) < 0) {
		perror("Unable to bind");
		exit(EXIT_FAILURE);
	}

	return s;
}

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = DTLS_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	return ctx;
}

static int pass(char *buf, int size, int rwflag, void *userdata)
{
	char *pass = "12138";
	strncpy(buf, (char *)pass, size);
	buf[strlen(pass)] = '\0';
	return strlen(pass);
}

#define COOKIE_SECRET_LENGTH 32
int cookie_initialized = 0;
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	PEER peer;

	/* Initialize a random secret */
	if (!cookie_initialized) {
		if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH)) {
			printf("error setting random cookie secret\n");
			return 0;
		}
		cookie_initialized = 1;
	}

	/* Read peer information */
	(void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
	case AF_INET:
		length += sizeof(struct in_addr);
		break;
	case AF_INET6:
		length += sizeof(struct in6_addr);
		break;
	default:
		OPENSSL_assert(0);
		break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char *)OPENSSL_malloc(length);

	if (buffer == NULL) {
		printf("out of memory\n");
		return 0;
	}

	switch (peer.ss.ss_family) {
	case AF_INET:
		memcpy(buffer,
		       &peer.s4.sin_port,
		       sizeof(in_port_t));
		memcpy(buffer + sizeof(peer.s4.sin_port),
		       &peer.s4.sin_addr,
		       sizeof(struct in_addr));
		break;
	case AF_INET6:
		memcpy(buffer,
		       &peer.s6.sin6_port,
		       sizeof(in_port_t));
		memcpy(buffer + sizeof(in_port_t),
		       &peer.s6.sin6_addr,
		       sizeof(struct in6_addr));
		break;
	default:
		OPENSSL_assert(0);
		break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void *)cookie_secret, COOKIE_SECRET_LENGTH,
	     (const unsigned char *)buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	PEER peer;

	/* If secret isn't initialized yet, the cookie can't be valid */
	if (!cookie_initialized)
		return 0;

	/* Read peer information */
	(void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
	case AF_INET:
		length += sizeof(struct in_addr);
		break;
	case AF_INET6:
		length += sizeof(struct in6_addr);
		break;
	default:
		OPENSSL_assert(0);
		break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char *)OPENSSL_malloc(length);

	if (buffer == NULL) {
		printf("out of memory\n");
		return 0;
	}

	switch (peer.ss.ss_family) {
	case AF_INET:
		memcpy(buffer,
		       &peer.s4.sin_port,
		       sizeof(in_port_t));
		memcpy(buffer + sizeof(in_port_t),
		       &peer.s4.sin_addr,
		       sizeof(struct in_addr));
		break;
	case AF_INET6:
		memcpy(buffer,
		       &peer.s6.sin6_port,
		       sizeof(in_port_t));
		memcpy(buffer + sizeof(in_port_t),
		       &peer.s6.sin6_addr,
		       sizeof(struct in6_addr));
		break;
	default:
		OPENSSL_assert(0);
		break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void *)cookie_secret, COOKIE_SECRET_LENGTH,
	     (const unsigned char *)buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
		return 1;

	return 0;
}

static int my_pref_list[] = {
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
	SSL_CTX_set_verify(ctx, SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, NULL);

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

	SSL_CTX_set1_curves(ctx, my_pref_list, sizeof(my_pref_list) / sizeof(int));

	SSL_CTX_set_read_ahead(ctx, 1);
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);
}

static void 
ssl_readcb(struct bufferevent * bev, void * arg)
{
   //将输入缓存区的数据输出
   struct evbuffer *in = bufferevent_get_input(bev);
   printf("Received %zu bytes\n", evbuffer_get_length(in));
   printf("----- data ----\n");
   printf("%.*s\n", (int)evbuffer_get_length(in), evbuffer_pullup(in, -1));
   //将输入缓存区的数据放入输出缓存区发生到客户端
   bufferevent_write_buffer(bev, in);
}

int timeout = 0;
static void ssl_timeout(struct bufferevent *bev, short what, void *arg)
{
	SSL *ssl = (SSL *) arg;
	printf("timeout \n");
	if(++timeout > 3) {
		bufferevent_free(bev);
		SSL_shutdown(ssl);
		printf("close \n");
	}
	//struct evbuffer *in = bufferevent_get_input(bev);
}

void commit_new_socket(int fd, SSL *ssl)
{
	int firstflg = 0;
	if (evbase == NULL) {
		evbase = event_base_new();
		firstflg = 1;
	}

	auto bev = bufferevent_openssl_socket_new(evbase, fd, ssl,
					     BUFFEREVENT_SSL_OPEN,
					     BEV_OPT_CLOSE_ON_FREE);

	bufferevent_enable(bev, EV_READ);
	bufferevent_enable(bev, EV_WRITE);
	bufferevent_enable(bev, EV_TIMEOUT);
	bufferevent_setcb(bev, ssl_readcb, NULL, ssl_timeout, ssl);
	bufferevent_settimeout(bev, 5, 0);
	char buf[] = "Hello, this is ECHO\n";
	bufferevent_write(bev, buf, sizeof(buf));

	if (firstflg) {
		thread thread_eb(event_base_loop, evbase, 0);
		thread_eb.detach();
	}
}

void connection_handle(unique_ptr<pass_info> pinfo)
{
#define BUFFER_SIZE (1 << 16)
	ssize_t len;
	char buf[BUFFER_SIZE];
	char addrbuf[INET6_ADDRSTRLEN];
	SSL *ssl = pinfo->ssl;
	int fd, reading = 0, ret;
	const int on = 1, off = 0;
	struct timeval timeout;
	int num_timeouts = 0, max_timeouts = 5;
	int verbose = 1;
	int veryverbose = 1;
	fd = socket(pinfo->client_addr.ss.ss_family, SOCK_DGRAM, 0);
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, (socklen_t)sizeof(on));
	if (bind(fd, (const struct sockaddr *)&pinfo->server_addr, sizeof(struct sockaddr_in))) {
		perror("bind");
		goto cleanup;
	}
	if (connect(fd, (struct sockaddr *)&pinfo->client_addr, sizeof(struct sockaddr_in))) {
		perror("connect");
		goto cleanup;
	}
	/* Set new fd and set BIO to connected */
	BIO_set_fd(SSL_get_rbio(ssl), fd, BIO_NOCLOSE);
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &pinfo->client_addr.ss);
	do {
		ret = SSL_accept(ssl);
	} while (ret == 0);

	if (ret < 0) {
		perror("SSL_accept");
		printf("%s\n", ERR_error_string(ERR_get_error(), buf));
		goto cleanup;
	}
	/* Set and activate timeouts */
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	if (verbose) {
		if (pinfo->client_addr.ss.ss_family == AF_INET) {
			printf("\nThread %lx: accepted connection from %s:%d\n",
			       pthread_self(),
			       inet_ntop(AF_INET, &pinfo->client_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
			       ntohs(pinfo->client_addr.s4.sin_port));
		} else {
			printf("\nThread %lx: accepted connection from %s:%d\n",
			       pthread_self(),
			       inet_ntop(AF_INET6, &pinfo->client_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
			       ntohs(pinfo->client_addr.s6.sin6_port));
		}
	}

	if (veryverbose && SSL_get_peer_certificate(ssl)) {
		printf("------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)),
				      1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
		printf("\n------------------------------------------------------------\n\n");
	}

	commit_new_socket(fd,ssl);
	return;

	while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) && num_timeouts < max_timeouts) {
		reading = 1;
		while (reading) {
			len = SSL_read(ssl, buf, sizeof(buf));

			switch (SSL_get_error(ssl, len)) {
			case SSL_ERROR_NONE:
				if (verbose) {
					printf("Thread %lx: read %d bytes\n", pthread_self(), (int)len);
				}
				reading = 0;
				break;
			case SSL_ERROR_WANT_READ:
				/* Handle socket timeouts */
				if (BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)) {
					unsigned char buff[8];
					int ret = SSL_write(ssl, buff, 0);
					printf("keepalive = %d\n",ret);
					num_timeouts++;
					reading = 0;
				}
				/* Just try again */
				break;
			case SSL_ERROR_ZERO_RETURN:
				reading = 0;
				break;
			case SSL_ERROR_SYSCALL:
				printf("Socket read error: ");
				//if (!handle_socket_error())
				//	goto cleanup;
				reading = 0;
				break;
			case SSL_ERROR_SSL:
				printf("SSL read error: ");
				printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
				goto cleanup;
				break;
			default:
				printf("Unexpected error while reading!\n");
				goto cleanup;
				break;
			}
		}
		if (len > 0) {
			len = SSL_write(ssl, buf, len);

			switch (SSL_get_error(ssl, len)) {
			case SSL_ERROR_NONE:
				if (verbose) {
					printf("Thread %lx: wrote %d bytes\n", pthread_self(), (int)len);
				}
				break;
			case SSL_ERROR_WANT_WRITE:
				/* Can't write because of a renegotiation, so
					 * we actually have to retry sending this message...
					 */
				break;
			case SSL_ERROR_WANT_READ:
				/* continue with reading */
				break;
			case SSL_ERROR_SYSCALL:
				printf("Socket write error: ");
				//if (!handle_socket_error())
				//	goto cleanup;
				reading = 0;
				break;
			case SSL_ERROR_SSL:
				printf("SSL write error: ");
				printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
				goto cleanup;
				break;
			default:
				printf("Unexpected error while writing!\n");
				goto cleanup;
				break;
			}
		}
	}
	SSL_shutdown(ssl);
cleanup:
	close(fd);
	SSL_free(ssl);
	if (verbose) {
		printf("Thread %lx: done, connection closed.\n", pthread_self());
	}
}

int main(int argc, char **argv)
{
	int sock;
	PEER server;
	SSL_CTX *ctx;

	SSL_library_init();

	OpenSSL_add_all_algorithms();

	SSL_load_error_strings();

	ctx = create_context();

	configure_context(ctx);

	sock = create_socket(server, 20000);

	/* Handle connections */
	while (1) {
		PEER client;
		unsigned int len = sizeof(client);
		memset(&client, 0, sizeof(sockaddr_in));
		BIO *bio = BIO_new_dgram(sock, BIO_NOCLOSE);
		timeval timeout;
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

		SSL *ssl;

		ssl = SSL_new(ctx);

		SSL_set_bio(ssl, bio, bio);
		SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

		while (DTLSv1_listen(ssl, (BIO_ADDR *)&client) <= 0) {
		}

		char addrbuf[1024];
		printf("listen Thread %lx: accepted connection from %s:%d\n",
			       pthread_self(),
			       inet_ntop(AF_INET, &client.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
			       ntohs(client.s4.sin_port));

		unique_ptr<pass_info> info = unique_ptr<pass_info>(new pass_info);
		memcpy(&info->server_addr, &server, sizeof(struct sockaddr_storage));
		memcpy(&info->client_addr, &client, sizeof(struct sockaddr_storage));
		info->ssl = ssl;
		thread p(connection_handle, std::move(info));
		p.detach();
	}

	close(sock);
	SSL_CTX_free(ctx);
}