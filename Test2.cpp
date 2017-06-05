//
// Created by root on 17-6-5.
//

#include <vector>
#include <unordered_map>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cinttypes>

#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cassert>


int main(){
	sockaddr_in sa = {0};

	sa.sin_addr.s_addr = htobe32(0x7f000001);
	sa.sin_port = htons(1500);
	sa.sin_family = AF_INET;

	SSL_library_init();
	SSL_CTX *sslctx = SSL_CTX_new(TLSv1_2_client_method());

	SSL *sslc = SSL_new(sslctx);




	int FD_Socket = socket(AF_INET, SOCK_STREAM, 0);

	connect(FD_Socket, (sockaddr *)&sa, sizeof sa);

	SSL_set_fd(sslc, FD_Socket);
	SSL_connect(sslc);




	char buf[4096];
//	memset(buf, 'a', 4096);

	SSL_write(sslc, buf, 4096);

	while (1) {
		int n = SSL_read(sslc, buf, 4096);
		fprintf(stderr, "ssl_read: %d\n", n);
		if (n)
		assert(buf[4095] == 'b');
	}


}