#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/select.h>
#include <poll.h>
#include <stdbool.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>

// Enable/disable logging - set to true to enable logs
static bool ENABLE_LOGGING = true;

// Logging macro - only logs if ENABLE_LOGGING is true
#define LOG(...)                          \
    do                                    \
    {                                     \
        if (ENABLE_LOGGING)               \
        {                                 \
            fprintf(stderr, __VA_ARGS__); \
            fflush(stderr);               \
        }                                 \
    } while (0)



// Monitored file descriptor - will be set by accept() hook
// Initialize to 0 for wolfsshd case (stdin), but accept() will update it
static int MONITORED_FD = 0;

// Function pointers for original syscalls
ssize_t (*original_recv)(int sockfd, void *buf, size_t len, int flags);
ssize_t (*original_read)(int fd, void *buf, size_t count);
ssize_t (*original_write)(int fd, const void *buf, size_t count);
ssize_t (*original_send)(int sockfd, const void *buf, size_t len, int flags);
int (*original_select)(int nfds, fd_set *readfds, fd_set *writefds,
                       fd_set *exceptfds, struct timeval *timeout);
int (*original_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int (*original_SSL_write)(SSL *ssl, const void *buf, int num);
int (*original_SSL_read)(SSL *ssl, void *buf, int num);
int (*original_SSL_accept)(SSL *ssl);
int (*original_shutdown)(int sockfd, int how);

__attribute__((constructor)) void register_original_functions()
{
    original_recv = (ssize_t (*)(int, void *, size_t, int))
        dlsym(RTLD_NEXT, "recv");
    original_read = (ssize_t (*)(int, void *, size_t))
        dlsym(RTLD_NEXT, "read");
    original_write = (ssize_t (*)(int, const void *, size_t))
        dlsym(RTLD_NEXT, "write");
    original_send = (ssize_t (*)(int, const void *, size_t, int))
        dlsym(RTLD_NEXT, "send");
    original_select = (int (*)(int, fd_set *, fd_set *, fd_set *, struct timeval *))
        dlsym(RTLD_NEXT, "select");
    original_accept = (int (*)(int, struct sockaddr *, socklen_t *))
        dlsym(RTLD_NEXT, "accept");
    original_SSL_write = dlsym(RTLD_NEXT, "SSL_write");
    original_SSL_read  = dlsym(RTLD_NEXT, "SSL_read");
    original_SSL_accept = dlsym(RTLD_NEXT, "SSL_accept");
    original_shutdown = (int (*)(int, int))dlsym(RTLD_NEXT, "shutdown");

    LOG("[OOB-HANDLER] Original functions loaded: recv=%p, read=%p, write=%p, send=%p, select=%p, accept=%p, SSL_write=%p, SSL_read=%p, SSL_accept=%p, shutdown=%p\n",
        (void *)original_recv, (void *)original_read, (void *)original_write,
        (void *)original_send, (void *)original_select, (void *)original_accept,
        (void *)original_SSL_write, (void *)original_SSL_read, (void *)original_SSL_accept,
        (void *)original_shutdown);
    if (!original_recv || !original_read || !original_write || !original_send || !original_select ||
        !original_SSL_write || !original_SSL_read || !original_SSL_accept || !original_shutdown)
    {
        LOG("[OOB-HANDLER] Error loading original functions\n");
    }
}


int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    int client_fd = original_accept(sockfd, addr, addrlen);

    if (client_fd >= 0)
    {
        // Update monitored fd to the newly accepted client socket
        MONITORED_FD = client_fd;

        char client_ip[INET_ADDRSTRLEN] = "unknown";
        int client_port = 0;

        if (addr && addr->sa_family == AF_INET)
        {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
            inet_ntop(AF_INET, &addr_in->sin_addr, client_ip, sizeof(client_ip));
            client_port = ntohs(addr_in->sin_port);
        }

        LOG("[SYSCALL] pid=%d accept: new client_fd=%d from %s:%d, MONITORED_FD updated\n",
            getpid(), client_fd, client_ip, client_port);
    }

    return client_fd;
}

static bool try_recv_oob_token(int fd)
{
    unsigned char b;
    ssize_t n = original_recv(fd, &b, 1, MSG_OOB | MSG_DONTWAIT);
    if (n == 1)
    {
        LOG("[OOB-HANDLER] pid=%d received OOB token on fd=%d via recv(), byte=0x%02x\n",
            getpid(), fd, b);
        // has_token = true;
        return true;
    }
    else if (n < 0)
    {
        // Log error for debugging
        // EINVAL on Linux means no OOB data available (normal case)
        // EAGAIN/EWOULDBLOCK means would block (also normal with MSG_DONTWAIT)
        int err = errno;
        if (err != EAGAIN && err != EWOULDBLOCK && err != EINVAL)
        {
            LOG("[OOB-HANDLER] pid=%d try_recv_oob_token failed: errno=%d (%s)\n",
                getpid(), err, strerror(err));
        }
    }
    return false;
}

// ssize_t recv(int sockfd, void *buf, size_t len, int flags)
// {
//     ssize_t ret = original_recv(sockfd, buf, len, flags);
//     if (sockfd == MONITORED_FD)
//         LOG("[SYSCALL] pid=%d recv: fd=%d len=%zu flags=%d => ret=%zd\n",
//             getpid(), sockfd, len, flags, ret);
//     return ret;
// }

ssize_t read(int fd, void *buf, size_t count)
{
    ssize_t ret = original_read(fd, buf, count);
    if (fd == MONITORED_FD){
        LOG("[SYSCALL] pid=%d read: fd=%d count=%zu => ret=%zd\n",
            getpid(), fd, count, ret);
        try_recv_oob_token(MONITORED_FD);
    }
    return ret;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    ssize_t ret = original_write(fd, buf, count);
    if (fd == MONITORED_FD)
        LOG("[SYSCALL] pid=%d write: fd=%d count=%zu => ret=%zd\n",
            getpid(), fd, count, ret);
    return ret;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    ssize_t ret = original_send(sockfd, buf, len, flags);
    if (sockfd == MONITORED_FD)
        LOG("[SYSCALL] pid=%d send: fd=%d len=%zu flags=%d => ret=%zd\n",
            getpid(), sockfd, len, flags, ret);
    return ret;
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    int ret = original_select(nfds, readfds, writefds, exceptfds, timeout);
    bool monitored_in_set =
        (readfds   && FD_ISSET(MONITORED_FD, readfds))  ||
        (writefds  && FD_ISSET(MONITORED_FD, writefds)) ||
        (exceptfds && FD_ISSET(MONITORED_FD, exceptfds));
    // if (monitored_in_set)
    LOG("[SYSCALL] pid=%d select: nfds=%d monitored_fd=%d => ret=%d\n",
        getpid(), nfds, MONITORED_FD, ret);
    return ret;
}

int SSL_write(SSL *ssl, const void *buf, int num)
{
    int ret = original_SSL_write(ssl, buf, num);
    if (SSL_get_fd(ssl) == MONITORED_FD)
        LOG("[SYSCALL] pid=%d SSL_write: fd=%d num=%d => ret=%d\n",
            getpid(), SSL_get_fd(ssl), num, ret);
    return ret;
}

int SSL_read(SSL *ssl, void *buf, int num)
{
    int ret = original_SSL_read(ssl, buf, num);
    if (SSL_get_fd(ssl) == MONITORED_FD)
        LOG("[SYSCALL] pid=%d SSL_read: fd=%d num=%d => ret=%d\n",
            getpid(), SSL_get_fd(ssl), num, ret);
    return ret;
}

int SSL_accept(SSL *ssl)
{
    int ret = original_SSL_accept(ssl);
    if (SSL_get_fd(ssl) == MONITORED_FD)
        LOG("[SYSCALL] pid=%d SSL_accept: fd=%d => ret=%d\n",
            getpid(), SSL_get_fd(ssl), ret);
    return ret;
}

int shutdown(int sockfd, int how)
{
    const char *how_str;
    switch (how)
    {
        case SHUT_RD:   how_str = "SHUT_RD";   break;
        case SHUT_WR:   how_str = "SHUT_WR";   break;
        case SHUT_RDWR: how_str = "SHUT_RDWR"; break;
        default:        how_str = "UNKNOWN";   break;
    }
    LOG("[SYSCALL] pid=%d shutdown: fd=%d how=%d (%s)\n",
        getpid(), sockfd, how, how_str);
    int ret = original_shutdown(sockfd, how);
    LOG("[SYSCALL] pid=%d shutdown: fd=%d => ret=%d%s%s\n",
        getpid(), sockfd, ret,
        ret < 0 ? " (FAILED) " : "",
        ret < 0 ? strerror(errno) : "");
    return ret;
}