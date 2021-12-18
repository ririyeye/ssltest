
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <uv.h>
#include <memory>
#include <thread>
#include <vector>
#include <list>
using namespace std;

enum OVERLAPPED_TYPE {
	RECV = 0,
	SEND,
};

enum SOCKET_STSTUS {
	NONE = 0x0,
	ACCEPTING = 0x1,
	CONNECTING = 0x2,
	HANDSHAKING = 0x4,
	CONNECTED = 0x8,
	RECEIVING = 0x10,
	SENDING = 0x20,
	CLOSING = 0x40,
	CLOSED = 0x80,
};

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

struct my_uv_udp_t : public uv_udp_t {
	uv_loop_t *loop = nullptr;
	struct sockaddr_in local_addr;
	SSL_CTX *ctx = nullptr;
	SSL *ssl = nullptr;
	static int static_index;
};

struct my_uv_udp_t_subnode : public my_uv_udp_t {
	uv_timer_t *timer = nullptr;
	struct sockaddr_in remote_addr;
	int timeout_index = 0;
	int index;
	BIO *bio[2];
	uint32_t status = NONE;
	list<vector<char> > app_recv;
	list<vector<char> > app_send;
};

struct uv_udp_send_extend : public uv_udp_send_t {
	char buff[4000];
	int len = 0;
	const int maxlen = 4000;
};

int my_uv_udp_t::static_index = 0;

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
	const char *pass = "12138";
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
#if 0
	/* Read peer information */
	(void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
#else
	my_uv_udp_t_subnode *my_socket = (my_uv_udp_t_subnode *)SSL_get_app_data(ssl);
	peer.s4 = my_socket->remote_addr;
	peer.ss.ss_family = AF_INET;
#endif
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

#if 0
	/* Read peer information */
	(void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
#else
	my_uv_udp_t_subnode *my_socket = (my_uv_udp_t_subnode *)SSL_get_app_data(ssl);
	peer.s4 = my_socket->remote_addr;
	peer.ss.ss_family = AF_INET;
#endif
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

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
	//struct my_uv_udp_t *init_socket = (struct my_uv_udp_t *)handle;
	//printf("index = %d,malloc %d\n",init_socket->index, suggested_size);
	(void)handle;
	const int bufflen = suggested_size;
	buf->base = new char[bufflen];
	buf->len = bufflen;
}

void cloes_cb(uv_handle_t *handle)
{
	//结束并释放资源
	my_uv_udp_t_subnode *my_socket = (my_uv_udp_t_subnode *)handle;
	fprintf(stdout, "close index %d\n", my_socket->index);
	if (my_socket->timer) {
		delete my_socket->timer;
		my_socket->timer = NULL;
	}
	//关闭ssl 释放资源
	SSL_free(my_socket->ssl);
	delete my_socket;
}

static void on_send(uv_udp_send_t *req, int status)
{
	delete req;
}

int send_bio_data(my_uv_udp_t_subnode *my_socket)
{
	int num = BIO_pending(my_socket->bio[SEND]);
	if (num <= 0) {
		return -1;
	}

	uv_udp_send_extend *snd = new uv_udp_send_extend();
	int wrlen = BIO_read(my_socket->bio[SEND], snd->buff, 4000);
	if (wrlen > 0) {
		uv_buf_t buff = uv_buf_init(snd->buff, wrlen);
		uv_udp_send(snd, my_socket, &buff, 1, 0, on_send);
		return 0;
	}
	return -2;
}

int shut_down_phase(my_uv_udp_t_subnode *my_socket)
{
	int ret_shutdown = SSL_shutdown(my_socket->ssl);
	printf("try to shut down ssl index = %d\n", my_socket->index);
	//1 成功 其他需要检查错误信息
	if (ret_shutdown == 1) {
		//shutdown 成功,等待socket 关闭
		return 0;
	}

	if (ret_shutdown == 0) {
		ret_shutdown = SSL_shutdown(my_socket->ssl);
		printf("ret_shutdown = %d\n", ret_shutdown);
	}

	int error_code = SSL_get_error(my_socket->ssl, ret_shutdown);
	printf("shutdown error ret = %d,error = %d\n", ret_shutdown, error_code);
	if (error_code == SSL_ERROR_WANT_WRITE || error_code == SSL_ERROR_WANT_READ) {
		send_bio_data(my_socket);
	}
	return -1;
}

void recv_timeout(uv_timer_t *handle)
{
	my_uv_udp_t_subnode *my_socket = (my_uv_udp_t_subnode *)handle->data;
	fprintf(stdout, "index %d timeout = %d\n", my_socket->index, ++my_socket->timeout_index);
	int can_close = 0;
	if (my_socket->timeout_index > 5) {
		if (my_socket->status & CONNECTED) {
			my_socket->status &= ~CONNECTED;
			my_socket->status |= CLOSING;
			my_socket->timeout_index = 0; //重置时间
			int ret = shut_down_phase(my_socket);
			if (ret == 0) {
				can_close = 1;
			}
		} else {
			can_close = 1;
		}
	}
	if (can_close) {
		fprintf(stdout, "try close index %d\n", my_socket->index);
		uv_timer_stop(handle);
		uv_unref((uv_handle_t *)handle);
		uv_close((uv_handle_t *)my_socket, cloes_cb);
	}
}

void session_process_recv(my_uv_udp_t_subnode *psession, char *buff, int len)
{
	if (len > 0) {
		int bytes = BIO_write(psession->bio[RECV], buff, len);
		int ssl_error = SSL_get_error(psession->ssl, bytes);
		if (bytes == len) {
		} else if (!BIO_should_retry(psession->bio[RECV])) {
			printf("ssl_error = %d!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n", ssl_error);
		}
	}

	int bytes = 0;
	do {
		char buff[4096];
		bytes = SSL_read(psession->ssl, buff, 4096);
		int ssl_error = SSL_get_error(psession->ssl, bytes);

		if (bytes > 0) {
			psession->app_recv.emplace_back(buff, buff + bytes);
			printf("get data %d = %s\n", bytes, buff);
		}

		if ((HANDSHAKING == (psession->status & HANDSHAKING)) && SSL_is_init_finished(psession->ssl)) {
			psession->status &= ~HANDSHAKING;
			psession->status |= CONNECTED;
		}

		if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
			send_bio_data(psession);
		}

		printf("get ssl error = %d,byte = %d\n", ssl_error, bytes);
	} while (bytes > 0);

	if ((psession->status & CONNECTED) == CONNECTED && psession->app_recv.size()) {
		auto itr = psession->app_recv.begin();
		int wrlen = SSL_write(psession->ssl, &itr->at(0), itr->size());
		int ssl_error = SSL_get_error(psession->ssl, wrlen);

		if (wrlen == itr->size()) {
			psession->app_recv.pop_front();
		}

		if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
			send_bio_data(psession);
		}
	}
}

static void on_read_ssl(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf,
			const struct sockaddr *addr, unsigned flags)
{
	my_uv_udp_t_subnode *my_socket = (my_uv_udp_t_subnode *)req;

	my_socket->timeout_index = 0;
	uv_timer_again(my_socket->timer);

	if ((my_socket->status & CLOSING) == CLOSING) {
		int bytes = BIO_write(my_socket->bio[RECV], buf->base, nread);
		
		int ret = shut_down_phase(my_socket);
		//ssl shutdown 完成
		if (ret == 0) {
			fprintf(stdout, "try close index %d\n", my_socket->index);
			uv_timer_stop(my_socket->timer);
			uv_unref((uv_handle_t *)my_socket->timer);
			uv_close((uv_handle_t *)my_socket, cloes_cb);
		}
	} else {
		session_process_recv(my_socket, buf->base, nread);
	}
	delete[] buf->base;
}

static void on_send_ssl(uv_udp_send_t *req, int status)
{
	delete req;
	if (status) {
		fprintf(stderr, "uv_udp_send_cb error: %s\n", uv_strerror(status));
	}
}

static void on_read_first(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf,
			  const struct sockaddr *addr, unsigned flags)
{
	(void)flags;
	if (nread < 0) {
		fprintf(stderr, "Read error %s\n", uv_err_name(nread));
		uv_close((uv_handle_t *)req, NULL);
		free(buf->base);
		return;
	}

	if (nread > 0) {
		char sender[17] = { 0 };
		struct my_uv_udp_t *init_socket = (struct my_uv_udp_t *)req;
		uv_ip4_name((const struct sockaddr_in *)addr, sender, 16);
		fprintf(stderr, "Recv first from %s,port=%d,%ld\n", sender, ((struct sockaddr_in *)addr)->sin_port, nread);
		//when first time recv,bind remote ip,port to new socket
		my_uv_udp_t_subnode *my_socket = new my_uv_udp_t_subnode();
		my_socket->loop = init_socket->loop;
		my_socket->index = my_uv_udp_t::static_index++;
		memcpy(&my_socket->local_addr, &init_socket->local_addr, sizeof(struct sockaddr_in));

		uv_udp_init(my_socket->loop, my_socket);
		uv_udp_bind(my_socket, (sockaddr *)&my_socket->local_addr, UV_UDP_REUSEADDR);
		uv_udp_connect(my_socket, (const struct sockaddr *)addr);
		uv_udp_recv_start(my_socket, alloc_buffer, on_read_ssl);

		/* init new ssl */
		my_socket->ssl = SSL_new(init_socket->ctx);
		SSL_set_app_data(my_socket->ssl, my_socket);
		/* set up the memory-buffer BIOs */
		my_socket->bio[SEND] = BIO_new(BIO_s_mem());
		my_socket->bio[RECV] = BIO_new(BIO_s_mem());

		BIO_set_mem_eof_return(my_socket->bio[SEND], -1);
		BIO_set_mem_eof_return(my_socket->bio[RECV], -1);

		/* bind them together */
		SSL_set_bio(my_socket->ssl, my_socket->bio[RECV], my_socket->bio[SEND]);
		/* if on the client: SSL_set_connect_state(con); */
		my_socket->status |= HANDSHAKING;
		SSL_set_accept_state(my_socket->ssl);
		SSL_set_options(my_socket->ssl, SSL_OP_COOKIE_EXCHANGE);

		/* at this point buf will store the results (with a length of rc) */
		my_socket->timer = new uv_timer_t();
		my_socket->timeout_index = 0;
		my_socket->timer->data = my_socket;
		uv_timer_init(my_socket->loop, my_socket->timer);
		uv_timer_start(my_socket->timer, recv_timeout, 2000, 2000);

		/* setup end,start handshaking */
		session_process_recv(my_socket, buf->base, nread);
	}
	delete[] buf->base;
}

my_uv_udp_t *create_local_bind(uv_loop_t *loop, int port)
{
	my_uv_udp_t *ret = new my_uv_udp_t();

	ret->loop = loop;

	uv_ip4_addr("0.0.0.0", port, &ret->local_addr);

	uv_udp_init(loop, ret);

	uv_udp_bind(ret, (const struct sockaddr *)&ret->local_addr, UV_UDP_REUSEADDR);
	uv_udp_recv_start(ret, alloc_buffer, on_read_first);

	return ret;
}

int main(int argc, char **argv)
{
	uv_loop_t *loop = uv_default_loop();

	SSL_CTX *ctx;

	SSL_library_init();

	OpenSSL_add_all_algorithms();

	SSL_load_error_strings();

	ctx = create_context();

	configure_context(ctx);

	my_uv_udp_t *pserver = create_local_bind(loop, 20000);

	pserver->ctx = ctx;

	uv_run(loop, UV_RUN_DEFAULT);
}
