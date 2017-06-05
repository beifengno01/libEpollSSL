//
// Created by root on 17-5-31.
//

#include "EpollSSL.hpp"
#include <sys/signal.h>

char buff[4096] = {'a'};

int TestCallback(Reimu::EpollSSL::ConnectionContext *con_ctx, void *userp) {
	if (con_ctx->ConnectionTerminated) {
		fprintf(stderr, "TestCallback: Connection terminated!\n");
	} else {
		fprintf(stderr, "TestCallback: Connection is alive!\n");

//		if (con_ctx->ReadBytes()) {
//			fprintf(stderr, "TestCallback: Read %zu bytes!\n", con_ctx->ReadBytes());
////			fflush(stdout);
////			write(STDOUT_FILENO, io_ctx->ReadBuffer, io_ctx->ReadSize);
////			printf("\n");
//			write(STDOUT_FILENO, con_ctx->Read(), con_ctx->ReadBytes());
//			con_ctx->Write(con_ctx->Read(), con_ctx->ReadBytes());
//		}
		con_ctx->Write(buff, 4096);
	}

	return 0;
}

int main(){
	signal(SIGPIPE, SIG_IGN);
	Reimu::EpollSSL::GlobalInit();

	Reimu::EpollSSL es;

	es.Threads = 4;
	es.BindAddr.resize(sizeof(sockaddr_in));
	memset(es.BindAddr.data(), 0, es.BindAddr.size());
	sockaddr_in *sss = (sockaddr_in *)es.BindAddr.data();
	sss->sin_addr.s_addr = INADDR_ANY;
	sss->sin_family = AF_INET;
	sss->sin_port = htons(1500);
	es.CertPath = "/etc/ssl/certs/ssl-cert-snakeoil.pem";
	es.PrivKeyPath = "/etc/ssl/private/ssl-cert-snakeoil.key";
	es.Callback = &TestCallback;

	memset(buff, 'a', 4096);
	buff[4095] = 'b';
	es.Server();
}