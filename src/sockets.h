#ifndef SOCKETS_H_02_01_2020
#define SOCKETS_H_02_01_2020

#include <array>
#include <vector>
#include <algorithm>
#include <netdb.h>
#include <sys/epoll.h>

class SOCKETS {
    public:
    SOCKETS(
        void (*log_fun) (const char *, const char *, ...) =drop_log,
        const char *log_src ="Sockets"
    ) : logfrom(log_src)
      , log    (log_fun)
    {}
    ~SOCKETS() {}

    static const int EPOLL_MAX_EVENTS = 64;
    static const int NO_DESCRIPTOR = -1;

    inline bool init() {
        int retval = sigfillset(&sigset_all);
        if (retval == -1) {
            int code = errno;

            log(
                logfrom.c_str(), "sigfillset: %s (%s:%d)", strerror(code),
                __FILE__, __LINE__
            );

            return false;
        }
        else if (retval) {
            log(
                logfrom.c_str(),
                "sigfillset: unexpected return value %d (%s:%d)", retval,
                __FILE__, __LINE__
            );

            return false;
        }

        retval = sigemptyset(&sigset_none);
        if (retval == -1) {
            int code = errno;

            log(
                logfrom.c_str(), "sigemptyset: %s (%s:%d)", strerror(code),
                __FILE__, __LINE__
            );

            return false;
        }
        else if (retval) {
            log(
                logfrom.c_str(),
                "sigemptyset: unexpected return value %d (%s:%d)", retval,
                __FILE__, __LINE__
            );

            return false;
        }

        return true;
    }

    inline bool deinit() {
        bool success = true;

        for (size_t key_hash=0; key_hash<descriptors.size(); ++key_hash) {
            while (!descriptors[key_hash].empty()) {
                int descriptor = descriptors[key_hash].back().first;

                if (!close_and_clear(descriptor)) {
                    // If for some reason we couldn't close the descriptor,
                    // we still need to deallocate the related memmory.
                    pop(descriptor);
                    success = false;
                }
            }
        }

        return success;
    }

    inline int listen_ipv6(const char *port, bool exposed) {
        return listen(port, AF_INET6, exposed ? AI_PASSIVE : 0);
    }

    inline int listen_ipv4(const char *port, bool exposed) {
        return listen(port, AF_INET, exposed ? AI_PASSIVE : 0);
    }

    inline int listen_any(const char *port, bool exposed) {
        return listen(port, AF_UNSPEC, exposed ? AI_PASSIVE : 0);
    }

    inline int listen(const char *port, bool exposed =true) {
        return listen_ipv4(port, exposed);
    }

    inline void wait(int descriptor, int epoll_timeout =0) {
        for (size_t i=0, esz=epoll_events.size(); i<esz; ++i) {
            for (size_t j=0, dsz=epoll_events[i].size(); j<dsz; ++j) {
                int epoll_descriptor = epoll_events[i][j].first;

                if (get(epoll_descriptor).second != descriptor) continue;

                epoll_event *events = &(epoll_events[i][j].second->at(1));

                wait(
                    epoll_descriptor,
                    &(epoll_events[i][j].second->at(0)),
                    events, int(epoll_events[i][j].second->size()-1),
                    epoll_timeout
                );

                return;
            }
        }
    }

    private:
    static void drop_log(const char *, const char *, ...) {}

    inline void wait(
        int epoll_descriptor, epoll_event *event, epoll_event *events, int len,
        int timeout =0
    ) {
        int pending = epoll_pwait(
            epoll_descriptor, events, len, timeout, &sigset_none
        );

        if (pending == -1) {
            int code = errno;

            if (code == EINTR) return;

            log(
                logfrom.c_str(), "epoll_pwait: %s (%s:%d)", strerror(code),
                __FILE__, __LINE__
            );

            return;
        }
        else if (pending < 0) {
            log(
                logfrom.c_str(),
                "epoll_pwait: unexpected return value %d (%s:%d)", pending,
                __FILE__, __LINE__
            );

            return;
        }

        for (int i=0; i<pending; ++i) {
            const int d = events[i].data.fd;

            if ((  events[i].events & EPOLLERR )
            ||  (  events[i].events & EPOLLHUP )
            ||  (!(events[i].events & EPOLLIN) )) {
                int socket_error = 0;
                socklen_t socket_errlen = sizeof(socket_error);

                if (events[i].events & EPOLLERR) {
                    int retval = getsockopt(
                        d, SOL_SOCKET, SO_ERROR, (void *) &socket_error,
                        &socket_errlen
                    );

                    if (retval) {
                        if (retval == -1) {
                            int code = errno;

                            log(
                                logfrom.c_str(), "getsockopt: %s (%s:%d)",
                                strerror(code), __FILE__, __LINE__
                            );
                        }
                        else {
                            log(
                                logfrom.c_str(),
                                "getsockopt: unexpected return value %d "
                                "(%s:%d)", retval, __FILE__, __LINE__
                            );
                        }
                    }
                    else {
                        if (socket_error == EPIPE
                        &&  get(d).second != NO_DESCRIPTOR) {
                            log(
                                logfrom.c_str(),
                                "Client of descriptor %d disconnected.", d,
                                __FILE__, __LINE__
                            );
                        }
                        else {
                            log(
                                logfrom.c_str(),
                                "epoll error on descriptor %d: %s (%s:%d)", d,
                                strerror(socket_error), __FILE__, __LINE__
                            );
                        }
                    }
                }
                else {
                    log(
                        logfrom.c_str(),
                        "unknown error on descriptor %d (%s:%d)", d,
                        __FILE__, __LINE__
                    );
                }

                if (!close_and_clear(d)) {
                    pop(d);
                }

                continue;
            }

            if (get(d).second == NO_DESCRIPTOR) {
                // New incoming connection detected.

                struct sockaddr in_addr;
                char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
                socklen_t in_len = sizeof(in_addr);

                int client_descriptor{
                    accept4(d, &in_addr, &in_len, SOCK_CLOEXEC|SOCK_NONBLOCK)
                };

                if (client_descriptor < 0) {
                    if (client_descriptor == -1) {
                        int code = errno;

                        if (code != EAGAIN && code != EWOULDBLOCK) {
                            log(
                                logfrom.c_str(), "accept4: %s (%s:%d)",
                                strerror(code), __FILE__, __LINE__
                            );
                        }
                    }
                    else {
                        log(
                            logfrom.c_str(),
                            "accept4: unexpected return value %d (%s:%d)",
                            client_descriptor, __FILE__, __LINE__
                        );
                    }

                    continue;
                }

                size_t client_descriptor_key{
                    client_descriptor % descriptors.size()
                };

                descriptors[client_descriptor_key].emplace_back(
                    client_descriptor, int(d)
                );

                int retval = getnameinfo(
                    &in_addr, in_len, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
                    NI_NUMERICHOST|NI_NUMERICSERV
                );

                if (retval != 0) {
                    log(
                        logfrom.c_str(), "getnameinfo: %s (%s:%d)",
                        gai_strerror(retval), __FILE__, __LINE__
                    );
                }
                else {
                    log(
                        logfrom.c_str(),
                        "New connection %d from %s:%s.",
                        client_descriptor, hbuf, sbuf
                    );
                }

                event->data.fd = client_descriptor;
                event->events = EPOLLIN|EPOLLET;

                retval = epoll_ctl(
                    epoll_descriptor, EPOLL_CTL_ADD, client_descriptor, event
                );

                if (retval != 0) {
                    if (retval == -1) {
                        int code = errno;

                        log(
                            logfrom.c_str(), "epoll_ctl: %s (%s:%d)",
                            strerror(code), __FILE__, __LINE__
                        );
                    }
                    else {
                        log(
                            logfrom.c_str(),
                            "epoll_ctl: unexpected return value %d (%s:%d)",
                            retval, __FILE__, __LINE__
                        );
                    }

                    if (!close_and_clear(client_descriptor)) {
                        pop(client_descriptor);
                    }

                    continue;
                }
            }
            else {
                // New data available to be read.

                log(
                    logfrom.c_str(),
                    "New incoming data on descriptor %d (%s:%d)", d,
                    __FILE__, __LINE__
                );
            }
        }
    }

    inline int listen(const char *port, int family, int ai_flags =AI_PASSIVE) {
        int descriptor = create_and_bind(port, family, ai_flags);

        if (descriptor == NO_DESCRIPTOR) return NO_DESCRIPTOR;

        int retval = ::listen(descriptor, SOMAXCONN);
        if (retval != 0) {
            if (retval == -1) {
                int code = errno;

                log(
                    logfrom.c_str(), "listen: %s (%s:%d)", strerror(code),
                    __FILE__, __LINE__
                );
            }
            else {
                log(
                    logfrom.c_str(),
                    "listen: unexpected return value %d (%s:%d)", retval,
                    __FILE__, __LINE__
                );
            }

            if (!close_and_clear(descriptor)) {
                pop(descriptor);
            }

            return NO_DESCRIPTOR;
        }

        int epoll_descriptor = create_epoll_and_bind(descriptor);

        if (epoll_descriptor == NO_DESCRIPTOR) {
            if (!close_and_clear(descriptor)) {
                pop(descriptor);
            }

            return NO_DESCRIPTOR;
        }

        return descriptor;
    }

    inline int create_epoll_and_bind(int descriptor) {
        if (descriptor == NO_DESCRIPTOR) return NO_DESCRIPTOR;

        int epoll_descriptor = epoll_create1(0);

        if (epoll_descriptor < 0) {
            if (epoll_descriptor == -1) {
                int code = errno;

                log(
                    logfrom.c_str(), "epoll_create1: %s (%s:%d)",
                    strerror(code), __FILE__, __LINE__
                );
            }
            else {
                log(
                    logfrom.c_str(),
                    "epoll_create1: unexpected return value %d (%s:%d)",
                    epoll_descriptor, __FILE__, __LINE__
                );
            }

            return NO_DESCRIPTOR;
        }

        size_t descriptor_key = epoll_descriptor % descriptors.size();

        descriptors[descriptor_key].emplace_back(
            epoll_descriptor, descriptor
        );

        size_t epoll_event_key = epoll_descriptor % epoll_events.size();

        epoll_events[epoll_event_key].emplace_back(
            epoll_descriptor,
            new (std::nothrow) std::array<epoll_event, 1+EPOLL_MAX_EVENTS>()
        );

        if (epoll_events[epoll_event_key].back().second == nullptr) {
            log(
                logfrom.c_str(), "new: out of memory (%s:%d)",
                __FILE__, __LINE__
            );

            if (!close_and_clear(epoll_descriptor)) {
                pop(epoll_descriptor);
            }

            return NO_DESCRIPTOR;
        }

        struct epoll_event *event{
            &(epoll_events[epoll_event_key].back().second->at(0))
        };

        event->data.fd = descriptor;
        event->events = EPOLLIN|EPOLLET;

        int retval{
            epoll_ctl(epoll_descriptor, EPOLL_CTL_ADD, descriptor, event)
        };

        if (retval != 0) {
            if (retval == -1) {
                int code = errno;

                log(
                    logfrom.c_str(), "epoll_ctl: %s (%s:%d)", strerror(code),
                    __FILE__, __LINE__
                );
            }
            else {
                log(
                    logfrom.c_str(),
                    "epoll_ctl: unexpected return value %d (%s:%d)",
                    retval, __FILE__, __LINE__
                );
            }

            if (!close_and_clear(epoll_descriptor)) {
                pop(epoll_descriptor);
            }

            return NO_DESCRIPTOR;
        }

        return epoll_descriptor;
    }

    inline int create_and_bind(
        const char *port, int family, int ai_flags =AI_PASSIVE
    ) {
        struct addrinfo hint =
#if __cplusplus <= 201703L
        __extension__
#endif
        addrinfo{
            .ai_flags     = ai_flags,
            .ai_family    = family,
            .ai_socktype  = SOCK_STREAM,
            .ai_protocol  = 0,
            .ai_addrlen   = 0,
            .ai_addr      = nullptr,
            .ai_canonname = nullptr,
            .ai_next      = nullptr
        };
        struct addrinfo *info = nullptr;

        int descriptor = NO_DESCRIPTOR;
        int retval = getaddrinfo(nullptr, port, &hint, &info);

        if (retval != 0) {
            log(
                logfrom.c_str(), "getaddrinfo: %s (%s:%d)",
                gai_strerror(retval), __FILE__, __LINE__
            );

            goto CleanUp;
        }

        for (struct addrinfo *next = info; next; next = next->ai_next) {
            descriptor = socket(
                next->ai_family,
                next->ai_socktype|SOCK_NONBLOCK|SOCK_CLOEXEC,
                next->ai_protocol
            );

            if (descriptor == -1) {
                int code = errno;

                log(
                    logfrom.c_str(), "socket: %s (%s:%d)", strerror(code),
                    __FILE__, __LINE__
                );

                continue;
            }

            size_t descriptor_key = descriptor % descriptors.size();

            descriptors[descriptor_key].emplace_back(
                descriptor, NO_DESCRIPTOR
            );

            int optval = 1;
            retval = setsockopt(
                descriptor, SOL_SOCKET, SO_REUSEADDR,
                (const void *) &optval, sizeof(optval)
            );

            if (retval != 0) {
                if (retval == -1) {
                    int code = errno;

                    log(
                        logfrom.c_str(), "setsockopt: %s (%s:%d)",
                        strerror(code), __FILE__, __LINE__
                    );
                }
                else {
                    log(
                        logfrom.c_str(),
                        "setsockopt: unexpected return value %d (%s:%d)",
                        retval, __FILE__, __LINE__
                    );
                }
            }
            else {
                retval = bind(descriptor, next->ai_addr, next->ai_addrlen);

                if (retval) {
                    if (retval == -1) {
                        int code = errno;

                        log(
                            logfrom.c_str(), "bind: %s (%s:%d)", strerror(code),
                            __FILE__, __LINE__
                        );
                    }
                    else {
                        log(
                            logfrom.c_str(),
                            "bind(%d, ?, %d) returned %d (%s:%d)",
                            descriptor, next->ai_addrlen, retval,
                            __FILE__, __LINE__
                        );
                    }
                }
                else break;
            }

            if (!close_and_clear(descriptor)) {
                log(
                    logfrom.c_str(), "failed to close descriptor %d (%s:%d)",
                    descriptor, __FILE__, __LINE__
                );

                pop(descriptor);
            }

            descriptor = NO_DESCRIPTOR;
        }

        CleanUp:
        if (info) freeaddrinfo(info);

        return descriptor;
    }

    inline size_t close_and_clear(int descriptor) {
        // Returns the number of descriptors successfully closed as a result.

        if (descriptor == NO_DESCRIPTOR) {
            log(
                logfrom.c_str(), "unexpected descriptor %d (%s:%d)", descriptor,
                __FILE__, __LINE__
            );

            return 0;
        }

        // Let's block all signals before calling close because we don't
        // want it to fail due to getting interrupted by a singal.
        int retval = sigprocmask(SIG_SETMASK, &sigset_all, &sigset_orig);
        if (retval == -1) {
            int code = errno;
            log(
                logfrom.c_str(), "sigprocmask: %s (%s:%d)", strerror(code),
                __FILE__, __LINE__
            );
            return 0;
        }
        else if (retval) {
            log(
                logfrom.c_str(),
                "sigprocmask: unexpected return value %d (%s:%d)", retval,
                __FILE__, __LINE__
            );

            return 0;
        }

        size_t closed = 0;
        retval = close(descriptor);

        if (retval) {
            if (retval == -1) {
                int code = errno;

                log(
                    logfrom.c_str(), "close(%d): %s (%s:%d)",
                    descriptor, strerror(code), __FILE__, __LINE__
                );
            }
            else {
                log(
                    logfrom.c_str(),
                    "close(%d): unexpected return value %d (%s:%d)",
                    descriptor, retval, __FILE__, __LINE__
                );
            }
        }
        else {
            ++closed;
            log(
                logfrom.c_str(), "Closed descriptor %d.", descriptor
            );

            std::pair<int, int> descriptor_data{pop(descriptor)};
            bool found = descriptor_data.first != NO_DESCRIPTOR;

            int close_children_of = NO_DESCRIPTOR;

            if (descriptor_data.second == NO_DESCRIPTOR) {
                close_children_of = descriptor;
            }

            if (!found) {
                log(
                    logfrom.c_str(),
                    "descriptor %d closed but not found (%s:%d)", descriptor,
                    __FILE__, __LINE__
                );
            }

            if (close_children_of != NO_DESCRIPTOR) {
                std::vector<int> to_be_closed;

                for (size_t key=0; key<descriptors.size(); ++key) {
                    for (size_t i=0, sz=descriptors[key].size(); i<sz; ++i) {
                        const std::pair<int, int> &d = descriptors[key][i];

                        if (d.second != close_children_of) {
                            continue;
                        }

                        to_be_closed.emplace_back(d.first);
                    }
                }

                std::for_each(
                    to_be_closed.begin(),
                    to_be_closed.end(),
                    [&](int d) {
                        retval = close(d);

                        if (retval == -1) {
                            int code = errno;
                            log(
                                logfrom.c_str(), "close(%d): %s (%s:%d)", d,
                                strerror(code), __FILE__, __LINE__
                            );
                        }
                        else if (retval != 0) {
                            log(
                                logfrom.c_str(),
                                "close(%d): unexpected return value %d (%s:%d)",
                                d, retval, __FILE__, __LINE__
                            );
                        }
                        else {
                            descriptor_data = pop(d);

                            if (descriptor_data.first == NO_DESCRIPTOR) {
                                log(
                                    logfrom.c_str(),
                                    "descriptor %d closed but not found "
                                    "(%s:%d)", d, __FILE__, __LINE__
                                );
                            }

                            ++closed;
                            log(
                                logfrom.c_str(), "Closed descriptor %d.", d
                            );
                        }
                    }
                );
            }
        }

        retval = sigprocmask(SIG_SETMASK, &sigset_orig, nullptr);
        if (retval == -1) {
            int code = errno;
            log(
                logfrom.c_str(), "sigprocmask: %s (%s:%d)", strerror(code),
                __FILE__, __LINE__
            );
        }
        else if (retval) {
            log(
                logfrom.c_str(),
                "sigprocmask: unexpected return value %d (%s:%d)", retval,
                __FILE__, __LINE__
            );
        }

        return closed;
    }

    inline std::pair<int, int> pop(int descriptor) {
        if (descriptor == NO_DESCRIPTOR) {
            return std::make_pair(NO_DESCRIPTOR, NO_DESCRIPTOR);
        }

        size_t key_hash = descriptor % descriptors.size();

        for (size_t i=0, sz=descriptors[key_hash].size(); i<sz; ++i) {
            const std::pair<int, int> &d = descriptors[key_hash][i];

            if (d.first != descriptor) continue;

            descriptors[key_hash][i] = descriptors[key_hash].back();
            descriptors[key_hash].pop_back();

            size_t event_key = descriptor % epoll_events.size();
            for (size_t j=0, esz=epoll_events[event_key].size(); j<esz; ++j) {
                auto &ev = epoll_events[event_key][j];

                if (ev.first != descriptor) continue;

                delete ev.second;

                epoll_events[event_key][j] = epoll_events[event_key].back();
                epoll_events[event_key].pop_back();

                break;
            }

            return std::make_pair(d.first, d.second);
        }

        return std::make_pair(NO_DESCRIPTOR, NO_DESCRIPTOR);
    }

    inline std::pair<int, int> get(int descriptor) {
        if (descriptor == NO_DESCRIPTOR) {
            return std::make_pair(NO_DESCRIPTOR, NO_DESCRIPTOR);
        }

        size_t key_hash = descriptor % descriptors.size();

        for (size_t i=0, sz=descriptors[key_hash].size(); i<sz; ++i) {
            const std::pair<int, int> &d = descriptors[key_hash][i];

            if (d.first != descriptor) continue;

            return std::make_pair(d.first, d.second);
        }

        return std::make_pair(NO_DESCRIPTOR, NO_DESCRIPTOR);
    }

    inline size_t count(int descriptor) {
        if (descriptor == NO_DESCRIPTOR) return 0;

        size_t key = descriptor % descriptors.size();

        for (size_t i=0, sz=descriptors[key].size(); i<sz; ++i) {
            if (descriptors[key][i].first == descriptor) return 1;
        }

        return 0;
    }

    std::string logfrom;
    void (*log)(const char *, const char *p_fmt, ...);
    std::array<
        std::vector<
            std::pair<
                int, std::array<epoll_event, 1+EPOLL_MAX_EVENTS> *
            >
        >, 1024
    > epoll_events;
    std::array<std::vector<std::pair<int, int>>, 1024> descriptors;
    sigset_t sigset_all;
    sigset_t sigset_none;
    sigset_t sigset_orig;
};

#endif
