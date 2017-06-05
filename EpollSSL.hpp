#ifndef Reimu_libEpollSSL_QwQ
#define Reimu_libEpollSSL_QwQ

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


namespace Reimu {
    class EpollSSL {
    public:
	enum ConnectionStates {
	    STATE_SSL_HANDSHAKE_STARTED = 0x1, STATE_SSL_HANDSHAKE_FINISHED = 0x2,
	    STATE_SSL_IO_QUEUED_READ = 0x10, STATE_SSL_IO_QUEUED_WRITE = 0x20
	};

	class IOWrapper;

	struct EpollThreadContext {
	    int FD_Epoll;
	    SSL_CTX *SSLContext;
	    struct epoll_event *EventsPending;
	    EpollSSL *Parent;
	};

	class ConnectionContext;

	size_t Threads = 0;

	std::vector<uint8_t> BindAddr;

	std::string CertPath;
	std::string PrivKeyPath;

	int (*Callback)(ConnectionContext *io_ctx, void *userp) = NULL;
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




    class EpollSSL::ConnectionContext {
    public:
	int FD = 0;
	uint32_t State = 0;
	struct epoll_event *Event = NULL;
	struct EpollThreadContext *ThreadContext = NULL;
	uint8_t ClientAddr[sizeof(sockaddr_in6)] = {0};
	SSL *SSLContext = NULL;
	int SSLError_Read = 0;
	int SSLError_Write = 0;
	std::vector<uint8_t> WriteBuffer;
	size_t WritePos = 0;
	uint8_t ReadBuffer[512] = {0};
	ssize_t ReadSize = 0;

	bool ConnectionTerminated = 0;
	bool EnableCallback = 0;

	inline void ApplyEpollModes() {
		epoll_ctl(ThreadContext->FD_Epoll, EPOLL_CTL_MOD, FD, Event);
	}
	inline void SetReadOnly() { Event->events |= EPOLLIN|EPOLLHUP|EPOLLET;
		Event->events &= ~EPOLLOUT; ApplyEpollModes(); }
	inline void SetWriteOnly() { Event->events |= EPOLLOUT|EPOLLHUP|EPOLLET;
		Event->events &= ~EPOLLIN; ApplyEpollModes(); }
	inline void SetReadWrite() { Event->events |= EPOLLIN|EPOLLOUT|EPOLLHUP|EPOLLET; ApplyEpollModes(); }

	inline size_t ReadBytes() {
		return ReadSize ? (size_t)ReadSize : 0;
	}

	inline u_char *Read() {
		return ReadBuffer;
	}

	inline void Read2Vector(std::vector<uint8_t> &v) {
		v.insert(v.end(), Read(), Read()+ReadBytes());
	}

	inline void Write(void *src, size_t n) {
		State |= STATE_SSL_IO_QUEUED_WRITE;
		SetWriteOnly();
		WriteBuffer.insert(WriteBuffer.end(), (u_char *)src, (u_char *)src+n);
	}

	inline void Write(std::vector<uint8_t> v) {
		State |= STATE_SSL_IO_QUEUED_WRITE;
		SetWriteOnly();
		WriteBuffer.insert(WriteBuffer.end(), v.begin(), v.end());
	}

	inline bool LastReadFinished() { return !(State & STATE_SSL_IO_QUEUED_READ); }
	inline bool LastWriteFinished() { return !(State & STATE_SSL_IO_QUEUED_WRITE); }

    };


//    class EpollSSL::IOWrapper {
//	inline void mod() {
//		epoll_ctl(ThreadContext->FD_Epoll, EPOLL_CTL_MOD, ConnectionContext->FD, Event);
//	}
//    public:
//	struct epoll_event *Event;
//	struct ConnectionContext *ConnectionContext;
//	struct EpollThreadContext *ThreadContext;
//
//	bool SSLSessionActive = 0;
//	bool ConnectionTerminated = 0;
//	bool LastWriteFinished = 0;
//
//	uint8_t *ReadBuffer;
//	size_t ReadSize = 0;
//
//	inline void Disconnect() { throw 0x10; }
//
//	inline void SetReadOnly() { Event->events |= EPOLLIN; Event->events &= ~EPOLLOUT; mod(); }
//	inline void SetWriteOnly() { Event->events |= EPOLLOUT; Event->events &= ~EPOLLIN; mod(); }
//	inline void SetReadWrite() { Event->events |= EPOLLIN; Event->events |= EPOLLOUT; mod(); }
//
//	inline void EnqueueWrite(void *src, size_t n) {
//		LastWriteFinished = 0;
//		Event->events &= ~EPOLLIN;
//		Event->events |= EPOLLOUT|EPOLLHUP|EPOLLET;
//
//		mod();
//		auto w = ConnectionContext->WriteBuffer; w->insert(w->end(), (u_char *)src, (u_char *)src+n);
//	}
//
//	IOWrapper() {}
//	IOWrapper(struct epoll_event *ev_cur, struct EpollThreadContext *parent_ctx);
//    };
}

#endif /* Reimu_libEpollSSL_QwQ */