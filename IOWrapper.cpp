//
// Created by root on 17-5-31.
//

#include "EpollSSL.hpp"

Reimu::EpollSSL::IOWrapper::IOWrapper(struct epoll_event *ev_cur, Reimu::EpollSSL::EpollThreadContext *parent_ctx) {
	Event = ev_cur;
	ThreadContext = parent_ctx;
	ConnectionContext = (struct ConnectionContext *)ev_cur->data.ptr;

	ReadBuffer = ThreadContext->ReadBuffer;
	ReadSize = ThreadContext->ReadSize;

	if (ConnectionContext->SSLState == 100) {
		SSLSessionActive = 1;
	}
}
