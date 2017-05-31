#ifndef Reimu_libEpollSSL_QwQ
#define Reimu_libEpollSSL_QwQ

#include <vector>
#include <unordered_map>

#include <cstdio>
#include <cstdlib>
#include <cstring>

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

namespace Reimu {
    class EpollSSL {
    public:
	class IOWrapper;

	struct EpollThreadContext {
	    int FD_Epoll;
	    SSL_CTX *SSLContext;
	    uint8_t ReadBuffer[2048];
	    ssize_t ReadSize;
	    struct epoll_event *EventsPending;
	    EpollSSL *Parent;
	};

	struct ConnectionContext {
	    int FD;
	    uint8_t ClientAddr[sizeof(sockaddr_in6)];
	    uint8_t SSLState;
	    SSL *SSLContext;
	    int SSLError_Read;
	    int SSLError_Write;
	    std::vector<uint8_t> *WriteBuffer;
	    size_t WritePos;
	};

	size_t Threads = 0;

	struct sockaddr *BindAddr = NULL;

	std::string CertPath;
	std::string PrivKeyPath;

	int (*Callback)(IOWrapper *io_ctx, void *userp) = NULL;
	void *CallbackUserPtr = NULL;

	static void GlobalInit();

	EpollSSL();
	~EpollSSL();

	void Server();

    private:
	int FD_Listener;
	pthread_t *ThreadPool = NULL;
	struct EpollThreadContext *ThreadContexts = NULL;

	static void *EpollThread(struct EpollThreadContext *ctx);

	void InitContext();
    };

    class EpollSSL::IOWrapper {
    public:
	struct epoll_event *Event;
	struct ConnectionContext *ConnectionContext;
	struct EpollThreadContext *ThreadContext;

	bool SSLSessionActive = 0;
	bool ConnectionTerminated = 0;

	uint8_t *ReadBuffer;
	ssize_t ReadSize;

	inline void Disconnect() { throw 0x10; }

	inline void SetReadOnly() { Event->events |= EPOLLIN; Event->events &= ~EPOLLOUT; }
	inline void SetWriteOnly() { Event->events |= EPOLLOUT; Event->events &= ~EPOLLIN; }
	inline void SetReadWrite() { Event->events |= EPOLLIN; Event->events |= EPOLLOUT; }

	inline void EnqueueWrite(void *src, size_t n) {
		auto w = ConnectionContext->WriteBuffer; w->insert(w->end(), (u_char *)src, (u_char *)src+n);
	}

	IOWrapper() {}
	IOWrapper(struct epoll_event *ev_cur, struct EpollThreadContext *parent_ctx);
    };
}

#endif /* Reimu_libEpollSSL_QwQ */