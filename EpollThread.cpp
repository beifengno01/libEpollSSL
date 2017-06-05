//
// Created by root on 17-5-31.
//


#include "EpollSSL.hpp"

static inline void free_conn(struct Reimu::EpollSSL::ConnectionContext *con) {
	if (con->SSLContext) {
		SSL_shutdown(con->SSLContext);
		SSL_free(con->SSLContext);
	}

	close(con->FD);
	delete con;
}

static inline void reimu_ssl_read(struct Reimu::EpollSSL::ConnectionContext *con) {

	con->ReadSize = SSL_read(con->SSLContext, con->ReadBuffer, sizeof(con->ReadBuffer)-64);

	fprintf(stderr, "[EpollSSL %p] [Thread %p] [SSLCtx %p] SSL_read(): %zd/%zu\n", con->ThreadContext->Parent,
		con->ThreadContext, con->SSLContext, con->ReadSize, sizeof(con->ReadBuffer));

	con->SSLError_Read = SSL_get_error(con->SSLContext, (int)con->ReadSize);

	fprintf(stderr, "[EpollSSL %p] [Thread %p] [SSLCtx %p] SSL error read: %d\n", con->ThreadContext->Parent,
		con->ThreadContext, con->SSLContext, con->SSLError_Read);

	switch (con->SSLError_Read) {
		case SSL_ERROR_NONE:
			con->State &= ~Reimu::EpollSSL::ConnectionStates::STATE_SSL_IO_QUEUED_READ;
			con->EnableCallback = 1;
			break;
		case SSL_ERROR_WANT_READ:
			con->SetReadOnly();
			con->State |= Reimu::EpollSSL::ConnectionStates::STATE_SSL_IO_QUEUED_READ;
			break;
		case SSL_ERROR_WANT_WRITE:
			con->SetWriteOnly();
			con->State |= Reimu::EpollSSL::ConnectionStates::STATE_SSL_IO_QUEUED_READ;
			break;
		case SSL_ERROR_ZERO_RETURN:
			con->ConnectionTerminated = 1;
			con->EnableCallback = 1;
			con->State &= ~Reimu::EpollSSL::ConnectionStates::STATE_SSL_IO_QUEUED_READ;
			break;
		default:
			con->ConnectionTerminated = 1;
			con->EnableCallback = 1;
			con->State &= ~Reimu::EpollSSL::ConnectionStates::STATE_SSL_IO_QUEUED_READ;
			break;
	}

}

static inline void reimu_ssl_write(struct Reimu::EpollSSL::ConnectionContext *con) {

	if (con->WriteBuffer.size()) {
		uint8_t *write_pos = con->WriteBuffer.data() + con->WritePos;
		int write_size = (int)(con->WriteBuffer.size() - con->WritePos);

		int rc_ssl_write = SSL_write(con->SSLContext, write_pos, write_size);

		fprintf(stderr, "[EpollSSL %p] [Thread %p] [SSLCtx %p] SSL_write(): %zd/%zu/%zu\n", con->ThreadContext->Parent,
			con->ThreadContext, con->SSLContext, rc_ssl_write, con->WritePos, con->WriteBuffer.size());

		con->SSLError_Write = SSL_get_error(con->SSLContext, rc_ssl_write);

		fprintf(stderr, "[EpollSSL %p] [Thread %p] [SSLCtx %p] SSL error write: %d\n", con->ThreadContext->Parent,
			con->ThreadContext, con->SSLContext, con->SSLError_Write);

		switch (con->SSLError_Write) {
			case SSL_ERROR_NONE:
				if (rc_ssl_write > 0)
					con->WritePos += rc_ssl_write;

				if (con->WritePos == con->WriteBuffer.size()) {
					con->State &= ~Reimu::EpollSSL::ConnectionStates::STATE_SSL_IO_QUEUED_WRITE;
					con->SetReadOnly();
					con->EnableCallback = 1;
					con->WritePos = 0;
					con->WriteBuffer.resize(0);
				}

				BIO_flush(con->SSLContext->wbio);

				break;
			case SSL_ERROR_WANT_READ:
				con->SetReadOnly();
				con->State |= Reimu::EpollSSL::ConnectionStates::STATE_SSL_IO_QUEUED_WRITE;
				break;
			case SSL_ERROR_WANT_WRITE:
				con->SetWriteOnly();
				con->State |= Reimu::EpollSSL::ConnectionStates::STATE_SSL_IO_QUEUED_WRITE;
				break;
			case SSL_ERROR_ZERO_RETURN:
				con->ConnectionTerminated = 1;
				con->EnableCallback = 1;
				con->State &= ~Reimu::EpollSSL::ConnectionStates::STATE_SSL_IO_QUEUED_WRITE;
				break;
			default:
				con->ConnectionTerminated = 1;
				con->EnableCallback = 1;
				con->State &= ~Reimu::EpollSSL::ConnectionStates::STATE_SSL_IO_QUEUED_WRITE;
				break;
		}

	} else {
		con->State &= ~Reimu::EpollSSL::ConnectionStates::STATE_SSL_IO_QUEUED_WRITE;
	}

}

void *Reimu::EpollSSL::EpollThread(struct EpollThreadContext *ctx) {
	fprintf(stderr, "[EpollSSL %p] [Thread %p] Thread started\n", ctx->Parent, ctx);

	ctx->EventsPending = (struct epoll_event *) alloca(128 * sizeof(struct epoll_event));

	ctx->FD_Epoll = epoll_create(65535);

	if (ctx->FD_Epoll != -1)
		fprintf(stderr, "[EpollSSL %p] [Thread %p] epoll context created\n", ctx->Parent, ctx);
	else {
		fprintf(stderr, "[EpollSSL %p] [Thread %p] FATAL: Failed to create epoll context\n", ctx->Parent, ctx);
		goto ending;
	}


	ctx->SSLContext = SSL_CTX_new(TLSv1_2_server_method());

	if (ctx->SSLContext) {
		fprintf(stderr, "[EpollSSL %p] [Thread %p] OpenSSL context initialized\n", ctx->Parent, ctx);
	} else {
		fprintf(stderr, "[EpollSSL %p] [Thread %p] FATAL: Unable to initialize OpenSSL context\n", ctx->Parent,
			ctx);
		goto ending;
	}

	if (SSL_CTX_use_certificate_file(ctx->SSLContext, ctx->Parent->CertPath.c_str(), SSL_FILETYPE_PEM)) {
		fprintf(stderr, "[EpollSSL %p] [Thread %p] OpenSSL: Loaded cert file `%s'\n", ctx->Parent, ctx,
			ctx->Parent->CertPath.c_str());
	} else {
		fprintf(stderr, "[EpollSSL %p] [Thread %p] OpenSSL: Failed to load cert file `%s'\n", ctx->Parent, ctx,
			ctx->Parent->CertPath.c_str());
		goto ending;
	}


	if (SSL_CTX_use_PrivateKey_file(ctx->SSLContext, ctx->Parent->PrivKeyPath.c_str(), SSL_FILETYPE_PEM)) {
		fprintf(stderr, "[EpollSSL %p] [Thread %p] OpenSSL: Loaded privkey file `%s'\n", ctx->Parent, ctx,
			ctx->Parent->PrivKeyPath.c_str());
	} else {
		fprintf(stderr, "[EpollSSL %p] [Thread %p] OpenSSL: Failed to load privkey file `%s'\n", ctx->Parent,
			ctx,
			ctx->Parent->PrivKeyPath.c_str());
		goto ending;
	}

	if (SSL_CTX_check_private_key(ctx->SSLContext)) {
		fprintf(stderr, "[EpollSSL %p] [Thread %p] OpenSSL: Cert/privkey pair is valid\n", ctx->Parent, ctx);
	} else {
		fprintf(stderr, "[EpollSSL %p] [Thread %p] OpenSSL: Cert/privkey pair is invalid\n", ctx->Parent, ctx);
		goto ending;
	}

	while (1) {

		int rc_epwait = epoll_wait(ctx->FD_Epoll, ctx->EventsPending, 128, -1); // Get events

		if (rc_epwait)
			fprintf(stderr, "[EpollSSL %p] [Thread %p] %d events to process\n", ctx->Parent, ctx,
				rc_epwait);
		else {
			fprintf(stderr, "[EpollSSL %p] [Thread %p] FATAL: epoll_wait() failed: %s\n", ctx->Parent, ctx,
				strerror(errno));
			goto ending;
		}

		for (int j = 0; j < rc_epwait; j++) { // Process events


			struct epoll_event *CurrentEvent = &ctx->EventsPending[j];
			ConnectionContext *CurrentConCtx = (ConnectionContext *) ctx->EventsPending[j].data.ptr;
			CurrentConCtx->Event = CurrentEvent;
			CurrentConCtx->ThreadContext = ctx;

			std::string epstrs;
			if (CurrentEvent->events & EPOLLET)
				epstrs += "EPOLLET|";

			if (CurrentEvent->events & EPOLLIN)
				epstrs += "EPOLLIN|";

			if (CurrentEvent->events & EPOLLOUT)
				epstrs += "EPOLLOUT|";

			if (CurrentEvent->events & EPOLLHUP)
				epstrs += "EPOLLHUP|";

			epstrs.pop_back();

			fprintf(stderr, "[EpollSSL %p] [Thread %p] Processing event %d/%d [%s]\n", ctx->Parent, ctx, j + 1,
				rc_epwait, epstrs.c_str());

			if (CurrentEvent->events & EPOLLHUP) { // Check for connection error
				CurrentConCtx->ConnectionTerminated = 1;

				int rc_cb = ctx->Parent->Callback(CurrentConCtx, ctx->Parent->CallbackUserPtr);

				if (rc_cb == 0) {
					if (epoll_ctl(ctx->FD_Epoll, EPOLL_CTL_DEL, CurrentConCtx->FD, CurrentEvent) <
					    0) {
						perror("epoll_ctl");
					}
					free_conn(CurrentConCtx);
				}
			} else { // Normal I/O operation

				if (!(CurrentConCtx->State & STATE_SSL_HANDSHAKE_FINISHED)) { // Attempt SSL handshake
					if (!(CurrentConCtx->State & STATE_SSL_HANDSHAKE_STARTED)) {
						CurrentConCtx->SSLContext = SSL_new(ctx->SSLContext);

						SSL_CTX_set_mode(ctx->SSLContext, SSL_MODE_ENABLE_PARTIAL_WRITE |
										  SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

						if (!SSL_set_fd(CurrentConCtx->SSLContext, CurrentConCtx->FD)) {
							fprintf(stderr,
								"[EpollSSL %p] [Thread %p] FATAL: SSL_set_fd() failed: %s "
									"SSLContext=%p, FD=%d\n", ctx->Parent, ctx,
								strerror(errno), CurrentConCtx->SSLContext,
								CurrentConCtx->FD);
							goto ending;
						}


						SSL_set_accept_state(CurrentConCtx->SSLContext);
						fprintf(stderr, "[EpollSSL %p] [Thread %p] SSL conn accepted\n",
							ctx->Parent, ctx);

						CurrentConCtx->State |= STATE_SSL_HANDSHAKE_STARTED;
					}

					if (CurrentConCtx->State & STATE_SSL_HANDSHAKE_STARTED) {
						fprintf(stderr, "[EpollSSL %p] [Thread %p] Attempting handshake\n",
							ctx->Parent, ctx);
						int rc_hs = SSL_do_handshake(CurrentConCtx->SSLContext);

						if (rc_hs != 1) {
							int err_hs = SSL_get_error(CurrentConCtx->SSLContext, rc_hs);

							if (err_hs == SSL_ERROR_WANT_WRITE) {
								CurrentConCtx->SetWriteOnly();
								fprintf(stderr, "[EpollSSL %p] [Thread %p] [SSLCtx %p] "
										"Handshaking: set fd write\n", ctx->Parent, ctx,
									CurrentConCtx->SSLContext);
							} else if (err_hs == SSL_ERROR_WANT_READ) {
								CurrentConCtx->SetReadOnly();
								fprintf(stderr, "[EpollSSL %p] [Thread %p] [SSLCtx %p] "
										"Handshaking: set fd read\n", ctx->Parent, ctx,
									CurrentConCtx->SSLContext);
							} else {
								fprintf(stderr, "[EpollSSL %p] [Thread %p] [SSLCtx %p] "
										"Handshake failed\n", ctx->Parent, ctx,
									CurrentConCtx->SSLContext);

								free_conn(CurrentConCtx);
							}
						} else {
							CurrentConCtx->State |= STATE_SSL_HANDSHAKE_FINISHED;
							fprintf(stderr, "[EpollSSL %p] [Thread %p] [SSLCtx %p] "
									"Handshake done\n", ctx->Parent, ctx,
								CurrentConCtx->SSLContext);

							CurrentConCtx->SetReadOnly();
						}
					}
					continue;
				} else { // SSL handshake already done

					if (CurrentConCtx->State & STATE_SSL_IO_QUEUED_WRITE) { // Last write unfinished
						reimu_ssl_write(CurrentConCtx);
					} else  { // Read anyway
						reimu_ssl_read(CurrentConCtx);
					}

					if (CurrentConCtx->EnableCallback) {
						int rc_cb = 0;
						rc_cb = ctx->Parent->Callback(CurrentConCtx,
									      ctx->Parent->CallbackUserPtr);
						if (rc_cb == 2) {
							free_conn(CurrentConCtx);
						}

						CurrentConCtx->EnableCallback = 0;
						CurrentConCtx->ReadSize = 0;
					}

					if (CurrentConCtx->ConnectionTerminated)
						free_conn(CurrentConCtx);

				}

			}

		}
	}

	ending:
	pthread_exit(NULL);
}
