//
// Created by root on 17-5-31.
//

#include "EpollSSL.hpp"

static const int one = 1;

void Reimu::EpollSSL::Server() {
	InitContext();

	for (size_t j=0; j<Threads; j++) {
		pthread_create(&ThreadPool[j], NULL, (void *(*)(void *))&EpollThread, &ThreadContexts[j]);
	}

	uint ConnCount = 0;

	FD_Listener = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(FD_Listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));

	if (bind(FD_Listener, BindAddr, sizeof(sockaddr_in)) == -1) {
		fprintf(stderr, "[EpollSSL %p] bind() error: %s\n", this, strerror(errno));
		throw -1;
	}

	if (listen(FD_Listener, 128) == -1) {
		fprintf(stderr, "[EpollSSL %p] listen() error: %s\n", this, strerror(errno));
		throw -2;
	}

	ConnectionContext *ConCtxBuf;
	int FD_Client;
	struct epoll_event EventBuffer;

	while (1) {


		if ((FD_Client = accept(FD_Listener, NULL, NULL)) == -1) {
			perror("accept error");
			continue;
		}

		fprintf(stderr, "[EpollSSL %p] New connection\n", this);

		fcntl(FD_Client, F_SETFL, O_NONBLOCK|fcntl(FD_Client, F_GETFL, 0));

		ConCtxBuf = (ConnectionContext *)calloc(1, sizeof(ConnectionContext));
		ConCtxBuf->FD = FD_Client;
		ConCtxBuf->WriteBuffer = new std::vector<uint8_t>;

		EventBuffer.events = EPOLLIN|EPOLLHUP;
		EventBuffer.data.ptr = ConCtxBuf;

		if (epoll_ctl(ThreadContexts[ConnCount % Threads].FD_Epoll, EPOLL_CTL_ADD, FD_Client, &EventBuffer) < 0) {
			perror("epoll_ctl");
			exit(1);
		}
	}

}
