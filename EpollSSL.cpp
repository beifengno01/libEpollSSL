
#include "EpollSSL.hpp"

void Reimu::EpollSSL::GlobalInit() {
	SSL_library_init();
	BIO *Bio = BIO_new_fd(2, BIO_NOCLOSE);
}

Reimu::EpollSSL::EpollSSL() {


}

Reimu::EpollSSL::~EpollSSL() {

}

void Reimu::EpollSSL::InitContext() {

	fprintf(stderr, "[EpollSSL %p] I: Using %zu threads\n", this, Threads);

	if (!ThreadPool)
		ThreadPool = (pthread_t *)malloc(sizeof(pthread_t)*Threads);

	fprintf(stderr, "[EpollSSL %p] I: Thread pool allocated at %p\n", this, ThreadPool);

	if (!ThreadContexts)
		ThreadContexts = (struct EpollThreadContext *)calloc(Threads, sizeof(struct EpollThreadContext));

	fprintf(stderr, "[EpollSSL %p] I: Thread contexts allocated at: ", this);

	for (size_t j=0; j<Threads; j++) {
		ThreadContexts[j].Parent = this;
		fprintf(stderr, "%p ", ThreadContexts+sizeof(struct EpollThreadContext)*j);
	}

	fprintf(stderr, "\n");

}

