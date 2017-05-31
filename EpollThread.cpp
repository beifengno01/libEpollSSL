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
	delete con->WriteBuffer;
	free(con);
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
			fprintf(stderr, "[EpollSSL %p] [Thread %p] Processing event %d/%d\n", ctx->Parent, ctx, j+1, rc_epwait);

			struct epoll_event *CurrentEvent = &ctx->EventsPending[j];
			struct ConnectionContext *CurrentConCtx = (struct ConnectionContext *) ctx->EventsPending[j].data.ptr;

			if (CurrentEvent->events & EPOLLHUP) { // Check for connection error
				IOWrapper IOCtx(CurrentEvent, ctx);
				IOCtx.ConnectionTerminated = 1;

				int rc_cb = ctx->Parent->Callback(&IOCtx, ctx->Parent->CallbackUserPtr);

				if (rc_cb == 0) {
					if (epoll_ctl(ctx->FD_Epoll, EPOLL_CTL_DEL, CurrentConCtx->FD, CurrentEvent) <
					    0) {
						perror("epoll_ctl");
					}
					free_conn(CurrentConCtx);
				}
			} else { // Normal I/O operation

				if (CurrentConCtx->SSLState != 100) { // Attempt SSL handshake
					if (CurrentConCtx->SSLState == 0) {
						CurrentConCtx->SSLContext = SSL_new(ctx->SSLContext);

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

						CurrentConCtx->SSLState = 1;
					}

					if (CurrentConCtx->SSLState == 1) {
						fprintf(stderr, "[EpollSSL %p] [Thread %p] Attempting handshake\n",
							ctx->Parent, ctx);
						int rc_hs = SSL_do_handshake(CurrentConCtx->SSLContext);

						if (rc_hs != 1) {
							int err_hs = SSL_get_error(CurrentConCtx->SSLContext, rc_hs);

							if (err_hs == SSL_ERROR_WANT_WRITE) {
								CurrentEvent->events |= EPOLLOUT;
								CurrentEvent->events &= ~EPOLLIN;
								fprintf(stderr, "[EpollSSL %p] [Thread %p] [SSLCtx %p] "
										"Handshaking: set fd write\n", ctx->Parent, ctx,
									CurrentConCtx->SSLContext);
							} else if (err_hs == SSL_ERROR_WANT_READ) {
								CurrentEvent->events |= EPOLLIN;
								CurrentEvent->events &= ~EPOLLOUT;
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
							CurrentConCtx->SSLState = 100;
							fprintf(stderr, "[EpollSSL %p] [Thread %p] [SSLCtx %p] "
									"Handshake done\n", ctx->Parent, ctx,
								CurrentConCtx->SSLContext);

							CurrentEvent->events |= EPOLLIN;
							CurrentEvent->events &= ~EPOLLOUT;
						}
						continue;
					}
				} else { // SSL handshake already done

					bool ConnectionTerminated = 0;

					if (CurrentEvent->events & EPOLLIN) {
						ctx->ReadSize = SSL_read(CurrentConCtx->SSLContext, ctx->ReadBuffer,
									 sizeof(ctx->ReadBuffer));

						fprintf(stderr, "[EpollSSL %p] [Thread %p] [SSLCtx %p] SSL_read(): %zd"
								"\n", ctx->Parent, ctx, CurrentConCtx->SSLContext,
							ctx->ReadSize);

						if (ctx->ReadSize <= 0) {
							CurrentConCtx->SSLError_Read = SSL_get_error(
								CurrentConCtx->SSLContext,
								(int) ctx->ReadSize);

							if ((ctx->ReadSize < 0 &&
							     CurrentConCtx->SSLError_Read != SSL_ERROR_WANT_READ)
							    || (ctx->ReadSize == 0)) {
								ConnectionTerminated = 1;
							}
						} else {
							CurrentConCtx->SSLError_Read = 0;
						}
					}

					if (CurrentEvent->events & EPOLLOUT) {
						if (CurrentConCtx->WriteBuffer->size()) {
							void *write_start_pos = CurrentConCtx->WriteBuffer->data() +
										CurrentConCtx->WritePos;
							size_t write_size = CurrentConCtx->WriteBuffer->size() -
									    CurrentConCtx->WritePos;
							ssize_t sent = SSL_write(CurrentConCtx->SSLContext,
										 write_start_pos, (int)write_size);

							if (sent <= 0) {
								CurrentConCtx->SSLError_Write = SSL_get_error(
									CurrentConCtx->SSLContext,
									(int)sent);

								if ((sent < 0 &&
								     CurrentConCtx->SSLError_Write != SSL_ERROR_WANT_WRITE)
								    || (sent == 0)) {
									ConnectionTerminated = 1;
								}
							} else {
								CurrentConCtx->SSLError_Write = 0;

								if (sent == write_size) {
									CurrentConCtx->WriteBuffer->clear();
									CurrentConCtx->WritePos = 0;
								} else {
									CurrentConCtx->WritePos += sent;
								}
							}
						}
					}

					IOWrapper IOCtx(CurrentEvent, ctx);
					IOCtx.ConnectionTerminated = ConnectionTerminated;

					int rc_cb = ctx->Parent->Callback(&IOCtx, ctx->Parent->CallbackUserPtr);

					if (rc_cb == 2 || ConnectionTerminated) {
						free_conn(CurrentConCtx);
					}
				}

			}

		}

	}

	ending:
	pthread_exit(NULL);
}
