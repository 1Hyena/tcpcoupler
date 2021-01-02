#ifndef SOCKETS_H_02_01_2020
#define SOCKETS_H_02_01_2020

#include <array>
#include <vector>
#include <netdb.h>
#include <sys/epoll.h>

class SOCKETS {
    public:
    SOCKETS(
        void (*log_fun) (const char *, const char *, ...) =drop_log,
        const char *log_src ="sockets"
    ) : logfrom(log_src)
      , log    (log_fun)
    {}
    ~SOCKETS() {}

    static const int EPOLL_MAX_EVENTS = 64;

    inline bool init() {
        if (sigfillset(&sigset_all) == -1) {
            log(
                logfrom.c_str(), "sigfillset failed (%s:%d)", __FILE__, __LINE__
            );

            return false;
        }

        if (sigemptyset(&sigset_none) == -1) {
            log(
                logfrom.c_str(), "sigemptyset failed (%s:%d)",
                __FILE__, __LINE__
            );

            return false;
        }

        return true;
    }

    inline bool deinit() {
        // Let's block all signals before calling close because we don't
        // want it to fail due to getting interrupted by a singal.
        if (sigprocmask(SIG_SETMASK, &sigset_all, &sigset_orig) == -1) {
            int code = errno;
            log(logfrom.c_str(), "sigprocmask: %s", strerror(code));
            return false;
        }

        bool success = true;

        for (size_t key_hash=0; key_hash<descriptors.size(); ++key_hash) {
            for (size_t i=0, sz=descriptors[key_hash].size(); i<sz; ++i) {
                const std::pair<int, int> &d = descriptors[key_hash][i];

                int descriptor = d.first;

                int retval = close(descriptor);

                if (retval == -1) {
                    int code = errno;
                    log(
                        logfrom.c_str(), "close(%d): %s (%s:%d)",
                        descriptor, strerror(code), __FILE__, __LINE__
                    );
                }
                else if (retval != 0) {
                    log(
                        logfrom.c_str(),
                        "close(%d): unexpected return value %d (%s:%d)",
                        descriptor, retval, __FILE__, __LINE__
                    );
                }
                else continue;

                success = false;
            }

            descriptors[key_hash].clear();
        }

        if (sigprocmask(SIG_SETMASK, &sigset_orig, nullptr) == -1) {
            int code = errno;
            log(logfrom.c_str(), "sigprocmask: %s", strerror(code));
        }

        while (!epoll_events.empty()) {
            auto &events = epoll_events.back();

            for (size_t i=0; i<events.size(); ++i) {
                delete events[i];
            }

            epoll_events.pop_back();
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

    private:
    static void drop_log(const char *, const char *, ...) {}

    inline int listen(const char *port, int family, int ai_flags =AI_PASSIVE) {
        int descriptor = create_and_bind(port, family, ai_flags);

        if (descriptor == -1) return -1;

        if (::listen(descriptor, SOMAXCONN) == -1) {
            int code = errno;

            log(
                logfrom.c_str(), "listen: %s (%s:%d)", strerror(code),
                __FILE__, __LINE__
            );

            safe_close(descriptor);

            return -1;
        }

        int epoll_descriptor = -1;

        if ((epoll_descriptor = epoll_create1(0)) == -1) {
            int code = errno;
            log(logfrom.c_str(), "epoll_create1: %s", strerror(code));

            safe_close(descriptor);

            return -1;
        }

        size_t epoll_event_index = epoll_events.size();
        epoll_events.resize(epoll_events.size() + 1);

        auto &events = epoll_events.back();

        for (size_t i=0; i<events.size(); ++i) {
            events[i] = new (std::nothrow) epoll_event;
        }

        struct epoll_event *event = events[0];

        event->data.fd = descriptor;
        event->events = EPOLLIN|EPOLLET;

        int retval{
            epoll_ctl(epoll_descriptor, EPOLL_CTL_ADD, descriptor, event)
        };
        int code = errno;

        if (retval != 0) {
            if (retval == -1) {
                log(logfrom.c_str(), "epoll_ctl: %s", strerror(code));
            }
            else if (retval != 0) {
                log(
                    logfrom.c_str(), "epoll_ctl: unexpected return value %d",
                    retval
                );
            }

            for (size_t i=0; i<events.size(); ++i) {
                delete events[i];
            }

            epoll_events.pop_back();

            safe_close(epoll_descriptor);
            safe_close(descriptor);

            return -1;
        }

        size_t descriptor_key = descriptor % descriptors.size();
        size_t epoll_descriptor_key = epoll_descriptor % descriptors.size();

        descriptors[descriptor_key].emplace_back(descriptor, 0);

        descriptors[epoll_descriptor_key].emplace_back(
            epoll_descriptor, descriptor
        );

        epoll_descriptors.emplace_back(epoll_descriptor, epoll_event_index);

        return descriptor;
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

        int descriptor = -1;
        int retval = getaddrinfo(nullptr, port, &hint, &info);

        if (retval != 0) {
            log(logfrom.c_str(), "getaddrinfo: %s", gai_strerror(retval));
            goto CleanUp;
        }

        for (struct addrinfo *next = info; next; next = next->ai_next) {
            descriptor = socket(
                next->ai_family,
                next->ai_socktype|SOCK_NONBLOCK|SOCK_CLOEXEC,
                next->ai_protocol
            );

            if (descriptor == -1) continue;

            int optval = 1;
            retval = setsockopt(
                descriptor, SOL_SOCKET, SO_REUSEADDR,
                (const void *) &optval, sizeof(optval)
            );

            if (retval == -1) {
                log(logfrom.c_str(), "setsockopt: %s", strerror(errno));
            }
            else {
                retval = bind(descriptor, next->ai_addr, next->ai_addrlen);

                if (!retval) break;
                else if (retval == -1) {
                    log(logfrom.c_str(), "bind: %s", strerror(errno));
                }
                else {
                    log(
                        logfrom.c_str(), "bind(%d, ?, %d) returned %d",
                        descriptor, next->ai_addrlen, retval
                    );
                }
            }

            if (!safe_close(descriptor)) {
                log(
                    logfrom.c_str(), "failed to close descriptor %d (%s:%d)",
                    descriptor, __FILE__, __LINE__
                );
            }

            descriptor = -1;
        }

        CleanUp:
        if (info) freeaddrinfo(info);

        return descriptor;
    }


    inline size_t safe_close(int descriptor) {
        // Returns the number of descriptors successfully closed as a result.

        if (descriptor < 0) {
            log(
                logfrom.c_str(), "unexpected descriptor %d (%s:%d)", descriptor,
                __FILE__, __LINE__
            );

            return 0;
        }

        // Let's block all signals before calling close because we don't
        // want it to fail due to getting interrupted by a singal.
        if (sigprocmask(SIG_SETMASK, &sigset_all, &sigset_orig) == -1) {
            int code = errno;
            log(logfrom.c_str(), "sigprocmask: %s", strerror(code));
            return 0;
        }

        size_t closed = 0;
        int retval = close(descriptor);

        if (retval == -1) {
            int code = errno;
            log(
                logfrom.c_str(), "close(%d): %s (%s:%d)",
                descriptor, strerror(code), __FILE__, __LINE__
            );
        }
        else if (retval != 0) {
            log(
                logfrom.c_str(), "close(%d): unexpected return value %d",
                descriptor, retval
            );
        }
        else ++closed;

        while (retval == 0) {
            int close_children_of = 0;
            size_t key_hash = descriptor % descriptors.size();
            bool found = false;

            for (size_t i=0, sz = descriptors[key_hash].size(); i<sz; ++i) {
                const std::pair<int, int> &d = descriptors[key_hash][i];

                if (d.first != descriptor) continue;

                if (!d.second) {
                    close_children_of = descriptor;
                }

                descriptors[key_hash][i] = descriptors[key_hash].back();
                descriptors[key_hash].pop_back();
                found = true;
                break;
            }

            if (!found) {
                log(
                    logfrom.c_str(),
                    "descriptor %d closed but not found (%s:%d)", descriptor,
                    __FILE__, __LINE__
                );
            }

            if (!close_children_of) break;

            for (size_t key_hash=0; key_hash<descriptors.size(); ++key_hash) {
                for (size_t i=0, sz=descriptors[key_hash].size(); i<sz;) {
                    const std::pair<int, int> &d = descriptors[key_hash][i];

                    ++i;

                    if (d.second != close_children_of) {
                        continue;
                    }

                    retval = close(d.first);

                    if (retval == -1) {
                        int code = errno;
                        log(
                            logfrom.c_str(), "close(%d): %s (%s:%d)", d.first,
                            strerror(code), __FILE__, __LINE__
                        );
                    }
                    else if (retval != 0) {
                        log(
                            logfrom.c_str(),
                            "close(%d): unexpected return value %d (%s:%d)",
                            d.first, retval, __FILE__, __LINE__
                        );
                    }
                    else {
                        descriptors[key_hash][i] = descriptors[key_hash].back();
                        descriptors[key_hash].pop_back();
                        --sz;
                        --i;
                        ++closed;
                    }
                }
            }

            TODO: BE SURE TO CLEAN UP EPOLL EVENTS HERE IF NEEDED

            break;
        }

        if (sigprocmask(SIG_SETMASK, &sigset_orig, nullptr) == -1) {
            int code = errno;
            log(logfrom.c_str(), "sigprocmask: %s", strerror(code));
        }

        return closed;
    }

    std::string logfrom;
    void (*log)(const char *, const char *p_fmt, ...);
    std::vector<std::pair<int, size_t>> epoll_descriptors;
    std::vector<std::array<epoll_event *, 1+EPOLL_MAX_EVENTS>> epoll_events;
    std::array<std::vector<std::pair<int, int>>, 1024> descriptors;
    sigset_t sigset_all;
    sigset_t sigset_none;
    sigset_t sigset_orig;
};

#endif
