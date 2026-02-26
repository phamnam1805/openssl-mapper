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
#include <time.h>

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

// Token state: true means library holds token, false means mapper holds token
// At start, mapper holds token (has_token = false)
static bool has_token = false;
static bool write_happened = false;
static bool connection_half_closed = false;
static struct timespec last_write_ts = {0, 0};

// Monitored file descriptor - will be set by accept() hook
// Initialize to 0 for wolfsshd case (stdin), but accept() will update it
static int MONITORED_FD = 0;

static void get_ts(struct timespec *ts)
{
    clock_gettime(CLOCK_MONOTONIC, ts);
}

static long ts_diff_us(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec) * 1000000L
         + (end->tv_nsec - start->tv_nsec) / 1000L;
}

// Function pointers for original syscalls
ssize_t (*original_recv)(int sockfd, void *buf, size_t len, int flags);
ssize_t (*original_read)(int fd, void *buf, size_t count);
ssize_t (*original_write)(int fd, const void *buf, size_t count);
ssize_t (*original_send)(int sockfd, const void *buf, size_t len, int flags);
int (*original_select)(int nfds, fd_set *readfds, fd_set *writefds,
                       fd_set *exceptfds, struct timeval *timeout);
int (*original_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int (*original_shutdown)(int sockfd, int how);
int (*original_SSL_write)(SSL *ssl, const void *buf, int num);
int (*original_SSL_read)(SSL *ssl, void *buf, int num);
int (*original_SSL_accept)(SSL *ssl);

static void log_fd_set(const char *name, fd_set *fds, int nfds)
{
    if (!fds) {
        LOG("  %s: (null)\n", name);
        return;
    }
    char buf[1024];
    int pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  %s: [", name);
    int found = 0;
    for (int i = 0; i < nfds && pos < (int)sizeof(buf) - 8; i++) {
        if (FD_ISSET(i, fds)) {
            pos += snprintf(buf + pos, sizeof(buf) - pos, found ? ", %d" : "%d", i);
            found++;
        }
    }
    snprintf(buf + pos, sizeof(buf) - pos, "]");
    LOG("%s\n", buf);
}

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
    original_shutdown = (int (*)(int, int))dlsym(RTLD_NEXT, "shutdown");
    
    original_SSL_write = dlsym(RTLD_NEXT, "SSL_write");
    original_SSL_read = dlsym(RTLD_NEXT, "SSL_read");
    original_SSL_accept = dlsym(RTLD_NEXT, "SSL_accept");

    // LOG("[OOB-HANDLER] Original functions loaded: recv=%p, read=%p, write=%p, send=%p, select=%p, accept=%p, SSL_write=%p, SSL_read=%p, SSL_accept=%p\n",
    //     (void *)original_recv, (void *)original_read, (void *)original_write,
    //     (void *)original_send, (void *)original_select, (void *)original_accept,
    //     (void *)original_SSL_write, (void *)original_SSL_read, (void *)original_SSL_accept, (void *)original_shutdown);
    if (!original_recv || !original_read || !original_write || !original_send || !original_select ||
        !original_SSL_write || !original_SSL_read || !original_SSL_accept || !original_shutdown)
    {
        LOG("[pid=%d] Error loading original functions\n", getpid());
    }
}

// Hook function for accept
// Capture the client socket fd when a connection is accepted
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

        LOG("[pid=%d] accept: new client_fd=%d from %s:%d, MONITORED_FD updated\n",
            getpid(), client_fd, client_ip, client_port);

        // Disable Nagle's algorithm for low-latency OOB communication
        int nodelay = 1;
        if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) < 0)
        {
            LOG("[pid=%d] failed to set TCP_NODELAY: %s\n", getpid(), strerror(errno));
        }

        has_token = false;
        write_happened = false;
    }

    return client_fd;
}

// Helper function to send OOB byte and release token
static void send_oob_token(int fd)
{
    struct timespec now;
    get_ts(&now);
    long delta_us = ts_diff_us(&last_write_ts, &now);

    unsigned char oob_byte = 'X';
    ssize_t n = original_send(fd, &oob_byte, 1, MSG_OOB);
    if (n == 1)
    {
        LOG("[pid=%d] sent OOB token on fd=%d, delta_since_last_write=%ld us\n",
            getpid(), fd, delta_us);
        has_token = false;
    }
    else
    {
        LOG("[pid=%d] failed to send OOB token on fd=%d: %s (delta=%ld us)\n",
            getpid(), fd, strerror(errno), delta_us);
    }
}

// Helper function to try receiving OOB byte (non-blocking)
static bool try_recv_oob_token(int fd)
{
    unsigned char b;
    ssize_t n = original_recv(fd, &b, 1, MSG_OOB | MSG_DONTWAIT);
    if (n == 1)
    {
        LOG("[pid=%d] received OOB token on fd=%d via recv(), byte=0x%02x\n",
            getpid(), fd, b);
        has_token = true;
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
            LOG("[pid=%d] try_recv_oob_token failed: errno=%d (%s)\n",
                getpid(), err, strerror(err));
        }
    }
    return false;
}

int SSL_read(SSL *ssl, void *buf, int num)
{
    if (SSL_get_fd(ssl) != MONITORED_FD){
        return original_SSL_read(ssl, buf, num);
    }
    if (has_token && write_happened)
    {
        LOG("[pid=%d] SSL_read: sockfd=%d, num=%d, has_token=%d => sending OOB token before SSL_read\n",
            getpid(), MONITORED_FD, num, has_token);
        send_oob_token(MONITORED_FD);
        write_happened = false;
    } else {
        LOG("[pid=%d] SSL_read: sockfd=%d, num=%d, has_token=%d\n",
                getpid(), MONITORED_FD, num, has_token);
    }
    int ret = original_SSL_read(ssl, buf, num);
    if(has_token && !write_happened){
        LOG("[pid=%d] SSL_read: sockfd=%d, num=%d, ret=%d, has_token=%d => sending OOB token after SSL_read\n",
            getpid(), MONITORED_FD, num, ret, has_token);
        send_oob_token(MONITORED_FD);
    } else {
        LOG("[pid=%d] SSL_read: sockfd=%d, num=%d, ret=%d, has_token=%d\n",
                getpid(), MONITORED_FD, num, ret, has_token);
    }
    return ret;
}

int SSL_accept(SSL *ssl)
{
    if (SSL_get_fd(ssl) != MONITORED_FD){
        return original_SSL_accept(ssl);
    }
    int ret = original_SSL_accept(ssl);
    LOG("[pid=%d] SSL_accept: sockfd=%d, ret=%d, has_token=%d\n",
            getpid(), MONITORED_FD, ret, has_token);
    return ret;
}

ssize_t read(int sockfd, void *buf, size_t len)
{
    if (sockfd != MONITORED_FD)
        return original_read(sockfd, buf, len);

    // if (has_token && write_happened)
    // {
    //     LOG("[pid=%d] read: sockfd=%d, len=%zu, has_token=%d => sending OOB token before read\n",
    //         getpid(), sockfd, len, has_token);
    //     send_oob_token(sockfd);
    //     write_happened = false;
    // }
    fd_set readfds;
    fd_set exceptfds;
    FD_ZERO(&readfds);
    FD_ZERO(&exceptfds);
    FD_SET(sockfd, &readfds);
    FD_SET(sockfd, &exceptfds);
    struct timeval timeout = {0, 0}; // Non-blocking select
    int sel_ret = original_select(sockfd + 1, &readfds, NULL, &exceptfds, &timeout);
    if (sel_ret > 0) {
        log_fd_set("readfds (before read)", &readfds, sockfd + 1);
        log_fd_set("exceptfds (before read)", &exceptfds, sockfd + 1);
    } else {
        if (has_token) {
            LOG("[pid=%d] read: sockfd=%d, len=%zu, sel_ret=%d, has_token=%d => sending OOB token before read\n",
                    getpid(), sockfd, len, sel_ret, has_token);
            send_oob_token(sockfd);
        }
    }

    int ret = original_read(sockfd, buf, len);
    LOG("[pid=%d] read: sockfd=%d, len=%zu, ret=%d, has_token=%d\n",
        getpid(), sockfd, len, ret, has_token);
    if (!has_token)
        try_recv_oob_token(sockfd);
    return ret;
}

// ssize_t write(int fd, const void *buf, size_t count)
// {
//     if (fd != MONITORED_FD)
//         return original_write(fd, buf, count);

//     ssize_t ret = original_write(fd, buf, count);
//     if (ret > 0)
//     {
//         get_ts(&last_write_ts); // Recording last writing timestamp
//         write_happened = true;
//     }
//     else
//         write_happened = false;
//     LOG("[pid=%d] write: fd=%d count=%zu => ret=%zd\n",
//         getpid(), fd, count, ret);
//     return ret;
// }

int shutdown(int sockfd, int how)
{
    if(sockfd != MONITORED_FD)
        return original_shutdown(sockfd, how);

    const char *how_str;
    switch (how)
    {
        case SHUT_RD:   how_str = "SHUT_RD";   break;
        case SHUT_WR:   how_str = "SHUT_WR";   break;
        case SHUT_RDWR: how_str = "SHUT_RDWR"; break;
        default:        how_str = "UNKNOWN";   break;
    }
    if(has_token){
        LOG("[pid=%d] shutdown: sockfd=%d, how=%d (%s), has_token=%d => sending OOB token before shutdown\n",
            getpid(), sockfd, how, how_str, has_token);
        send_oob_token(sockfd);
        write_happened = false;
    } else {
        LOG("[pid=%d] shutdown: sockfd=%d, how=%d (%s), has_token=%d => no OOB token sent\n",
            getpid(), sockfd, how, how_str, has_token);
    }
    int ret = original_shutdown(sockfd, how);
    connection_half_closed = ret == 0 ? true : false;
    LOG("[pid=%d] shutdown: fd=%d => ret=%d%s%s\n",
        getpid(), sockfd, ret,
        ret < 0 ? " (FAILED) " : "",
        ret < 0 ? strerror(errno) : "");
    return ret;
}



// int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
// {
//     LOG("[SYSCALL] pid=%d select: nfds=%d inside_ssl_accept=%d (before call)\n",
//         getpid(), nfds, inside_ssl_accept);
//     log_fd_set("readfds",   readfds,   nfds);
//     log_fd_set("writefds",  writefds,  nfds);
//     log_fd_set("exceptfds", exceptfds, nfds);

//     int ret = original_select(nfds, readfds, writefds, exceptfds, timeout);

//     bool monitored_in_set =
//         (readfds   && FD_ISSET(MONITORED_FD, readfds))  ||
//         (writefds  && FD_ISSET(MONITORED_FD, writefds)) ||
//         (exceptfds && FD_ISSET(MONITORED_FD, exceptfds));
//     bool write_ready = writefds && FD_ISSET(MONITORED_FD, writefds);
//     LOG("[SYSCALL] pid=%d select => ret=%d monitored_in_set=%d write_ready=%d\n",
//         getpid(), ret, monitored_in_set, write_ready);
//     log_fd_set("readfds (ready)",   readfds,   nfds);
//     log_fd_set("writefds (ready)",  writefds,  nfds);
//     log_fd_set("exceptfds (ready)", exceptfds, nfds);

//     return ret;
// }