#ifndef SOCKETS_H_02_01_2020
#define SOCKETS_H_02_01_2020

#include <array>
#include <vector>
#include <algorithm>
#include <netdb.h>
#include <sys/epoll.h>

class SOCKETS {
    public:
    static const int EPOLL_MAX_EVENTS = 64;
    static const int NO_DESCRIPTOR = -1;

    enum class FLAG : uint8_t {
        NONE      = 0,
        EPOLL     = 1,
        READ      = 2,
        WRITE     = 3,
        ACCEPT    = 4,
        CONNECT   = 5,
        DISCONNECT= 6,
        CLOSE     = 7,
        MAX_FLAGS = 8
    };

    private:
    struct record_type {
        std::array<uint32_t, static_cast<size_t>(FLAG::MAX_FLAGS)> flags;
        epoll_event *events;
        std::array<char, NI_MAXHOST> host;
        std::array<char, NI_MAXSERV> port;
        int descriptor;
        int parent;
    };

    struct flag_type {
        int descriptor;
        FLAG index;
    };

    static constexpr record_type make_record(int descriptor, int parent) {
#if __cplusplus <= 201703L
        __extension__
#endif
        record_type record{
            .flags      = {},
            .events     = nullptr,
            .host       = {'\0'},
            .port       = {'\0'},
            .descriptor = descriptor,
            .parent     = parent
        };

        for (auto i = 0; i != record.flags.size(); ++i) {
            record.flags[i] = std::numeric_limits<uint32_t>::max();
        }

        return record;
    }

    static constexpr flag_type make_flag(
        int descriptor =NO_DESCRIPTOR, FLAG index =FLAG::NONE
    ) {
        return
#if __cplusplus <= 201703L
        __extension__
#endif
        flag_type{
            .descriptor = descriptor,
            .index      = index
        };
    }

    public:
    SOCKETS(
        void (*log_fun) (const char *, const char *, ...) =drop_log,
        const char *log_src ="Sockets"
    ) : logfrom(log_src)
      , log    (log_fun)
    {}
    ~SOCKETS() {}

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
                int descriptor = descriptors[key_hash].back().descriptor;

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

    inline int next_connection() {
        static constexpr const size_t flg_connect_index{
            static_cast<size_t>(FLAG::CONNECT)
        };

        if (!flags[flg_connect_index].empty()) {
            int descriptor = flags[flg_connect_index].back().descriptor;
            rem_flag(descriptor, FLAG::CONNECT);
            return descriptor;
        }

        return NO_DESCRIPTOR;
    }

    inline int next_disconnection() {
        static constexpr const size_t flg_disconnect_index{
            static_cast<size_t>(FLAG::DISCONNECT)
        };

        if (!flags[flg_disconnect_index].empty()) {
            int descriptor = flags[flg_disconnect_index].back().descriptor;
            rem_flag(descriptor, FLAG::DISCONNECT);
            set_flag(descriptor, FLAG::CLOSE);
            return descriptor;
        }

        return NO_DESCRIPTOR;
    }

    inline const char *get_host(int descriptor) const {
        const record_type *record = find_record(descriptor);
        return record ? record->host.data() : "";
    }

    inline const char *get_port(int descriptor) const {
        const record_type *record = find_record(descriptor);
        return record ? record->port.data() : "";
    }

    inline bool serve(int descriptor, int timeout =0) {
        static constexpr const size_t flg_connect_index{
            static_cast<size_t>(FLAG::CONNECT)
        };

        static constexpr const size_t flg_disconnect_index{
            static_cast<size_t>(FLAG::DISCONNECT)
        };

        if (!flags[flg_connect_index].empty()) {
            // We postpone serving any descriptors until the application has
            // acknowledged all the new incoming connections.

            struct timespec ts;
            ts.tv_sec  = timeout / 1000;
            ts.tv_nsec = (timeout % 1000) * 1000000;

            pselect(0, nullptr, nullptr, nullptr, &ts, &sigset_none);

            return true;
        }

        std::vector<int> recbuf;

        for (size_t i=0; i<flags.size(); ++i) {
            FLAG flag = static_cast<FLAG>(i);

            recbuf.reserve(flags[i].size());

            for (size_t j=0, sz=flags[i].size(); j<sz; ++j) {
                int d = flags[i][j].descriptor;
                record_type *rec = find_record(d);

                if (d != descriptor && rec->parent != descriptor) continue;

                recbuf.emplace_back(d);
            }

            for (size_t j=0, sz=recbuf.size(); j<sz; ++j) {
                int d = recbuf[j];
                rem_flag(d, flag);

                switch (flag) {
                    case FLAG::EPOLL: {
                        if (handle_epoll(d, timeout)) continue;
                        break;
                    }
                    case FLAG::CONNECT:
                    case FLAG::DISCONNECT: {
                        // This descriptor has been marked for acknoledgement
                        // but the application has not done it yet.

                        set_flag(d, flag);
                        continue;
                    }
                    case FLAG::CLOSE: {
                        if (has_flag(d, FLAG::READ)) {
                            // We postpone normal closing until there is nothing
                            // left to read from this descriptor.

                            set_flag(d, FLAG::READ);
                            continue;
                        }

                        if (handle_close(d)) continue;
                        break;
                    }
                    case FLAG::ACCEPT: {
                        if (!flags[flg_disconnect_index].empty()) {
                            // We postpone the acceptance of new connections
                            // until all the recent disconnections have been
                            // acknowledged.

                            set_flag(d, flag);
                            continue;
                        }

                        if (handle_accept(d)) continue;
                        break;
                    }
                    case FLAG::WRITE: {
                        if (handle_write(d)) continue;
                        break;
                    }
                    case FLAG::READ: {
                        if (handle_read(d)) continue;
                        break;
                    }
                    default: break;
                }

                log(logfrom.c_str(), "%d -> FLAG %lu", d, i);
                return false;
            }

            recbuf.clear();
        }

        return true;
    }

    private:
    static void drop_log(const char *, const char *, ...) {}

    inline bool handle_close(int descriptor) {
        if (!close_and_clear(descriptor)) {
            pop(descriptor);
            return false;
        }

        return true;
    }

    inline bool handle_epoll(int epoll_descriptor, int timeout) {
        record_type *record = find_record(epoll_descriptor);
        epoll_event *events = &(record->events[1]);

        set_flag(epoll_descriptor, FLAG::EPOLL);

        int pending = epoll_pwait(
            epoll_descriptor, events, EPOLL_MAX_EVENTS, timeout, &sigset_none
        );

        if (pending == -1) {
            int code = errno;

            if (code == EINTR) return true;

            log(
                logfrom.c_str(), "epoll_pwait: %s (%s:%d)", strerror(code),
                __FILE__, __LINE__
            );

            return false;
        }
        else if (pending < 0) {
            log(
                logfrom.c_str(),
                "epoll_pwait: unexpected return value %d (%s:%d)", pending,
                __FILE__, __LINE__
            );

            return false;
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
                        record_type *rec = find_record(d);

                        if (socket_error != EPIPE
                        ||  rec == nullptr
                        ||  rec->parent == NO_DESCRIPTOR) {
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

                set_flag(d, FLAG::DISCONNECT);

                continue;
            }

            if (is_listener(d)) {
                set_flag(d, FLAG::ACCEPT);
            }
            else {
                set_flag(d, FLAG::READ);
            }
        }

        return true;
    }

    inline bool handle_read(int descriptor) {
        while (1) {
            ssize_t count;
            char buf[65536];

            count = ::read(descriptor, buf, sizeof(buf));
            if (count < 0) {
                if (count == -1) {
                    int code = errno;

                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        return true;
                    }

                    log(
                        logfrom.c_str(), "read(%d, ?, %lu): %s (%s:%d)",
                        descriptor, sizeof(buf), strerror(code),
                        __FILE__, __LINE__
                    );

                    break;
                }

                log(
                    logfrom.c_str(),
                    "read(%d, ?, %lu): unexpected return value %lld (%s:%d)",
                    descriptor, sizeof(buf), (long long)(count),
                    __FILE__, __LINE__
                );

                break;
            }
            else if (count == 0) {
                // End of file. The remote has closed the connection.
                break;
            }

            log(
                logfrom.c_str(), "%lld bytes were read from descriptor %d",
                (long long) count, descriptor
            );

            // Process buf here.

            set_flag(descriptor, FLAG::READ);

            return true;
        }

        set_flag(descriptor, FLAG::DISCONNECT);

        return true;
    }

    inline bool handle_write(int descriptor) {
        return true;
    }

    inline bool handle_accept(int descriptor) {
        // New incoming connection detected.
        int epoll_descriptor = NO_DESCRIPTOR;
        record_type *epoll_record = nullptr;

        static constexpr const size_t flag_index{
            static_cast<size_t>(FLAG::EPOLL)
        };

        for (size_t i=0, sz=flags[flag_index].size(); i<sz; ++i) {
            epoll_descriptor = flags[flag_index][i].descriptor;
            record_type *rec = find_record(epoll_descriptor);

            if (rec->parent == descriptor) {
                epoll_record = rec;
                break;
            }
        }

        if (!epoll_record) {
            log(
                logfrom.c_str(), "%s: %s (%s:%d)", __FUNCTION__,
                "epoll record could not be found", __FILE__, __LINE__
            );

            return false;
        }

        struct sockaddr in_addr;
        socklen_t in_len = sizeof(in_addr);

        int client_descriptor{
            accept4(
                descriptor, &in_addr, &in_len, SOCK_CLOEXEC|SOCK_NONBLOCK
            )
        };

        if (client_descriptor < 0) {
            if (client_descriptor == -1) {
                int code = errno;

                switch (code) {
#if EAGAIN != EWOULDBLOCK
                    case EAGAIN:
#endif
                    case EWOULDBLOCK: {
                        // Everything is normal.

                        return true;
                    }
                    case ENETDOWN:
                    case EPROTO:
                    case ENOPROTOOPT:
                    case EHOSTDOWN:
                    case ENONET:
                    case EHOSTUNREACH:
                    case EOPNOTSUPP:
                    case ENETUNREACH: {
                        // These errors are supposed to be temporary.

                        log(
                            logfrom.c_str(), "accept4: %s (%s:%d)",
                            strerror(code), __FILE__, __LINE__
                        );

                        set_flag(descriptor, FLAG::ACCEPT);

                        return true;
                    }
                    case EINTR: {
                        set_flag(descriptor, FLAG::ACCEPT);

                        return true;
                    }
                    default: {
                        // These errors are fatal.

                        log(
                            logfrom.c_str(), "accept4: %s (%s:%d)",
                            strerror(code), __FILE__, __LINE__
                        );

                        break;
                    }
                }
            }
            else {
                log(
                    logfrom.c_str(),
                    "accept4: unexpected return value %d (%s:%d)",
                    client_descriptor, __FILE__, __LINE__
                );
            }

            // Something has gone terribly wrong.

            if (!close_and_clear(descriptor)) {
                pop(descriptor);
            }

            return false;
        }

        size_t client_descriptor_key{
            client_descriptor % descriptors.size()
        };

        descriptors[client_descriptor_key].emplace_back(
            make_record(client_descriptor, int(descriptor))
        );

        record_type *client_record = find_record(client_descriptor);

        int retval = getnameinfo(
            &in_addr, in_len,
            client_record->host.data(), socklen_t(client_record->host.size()),
            client_record->port.data(), socklen_t(client_record->port.size()),
            NI_NUMERICHOST|NI_NUMERICSERV
        );

        if (retval != 0) {
            log(
                logfrom.c_str(), "getnameinfo: %s (%s:%d)",
                gai_strerror(retval), __FILE__, __LINE__
            );

            client_record->host[0] = '\0';
            client_record->port[0] = '\0';
        }

        epoll_event *event = &(epoll_record->events[0]);

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
        }

        set_flag(descriptor, FLAG::ACCEPT);
        set_flag(client_descriptor, FLAG::CONNECT);

        return true;
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

        set_flag(descriptor, FLAG::ACCEPT);

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
            make_record(epoll_descriptor, descriptor)
        );

        record_type &record = descriptors[descriptor_key].back();

        record.events = new (std::nothrow) epoll_event [1+EPOLL_MAX_EVENTS];

        if (record.events == nullptr) {
            log(
                logfrom.c_str(), "new: out of memory (%s:%d)",
                __FILE__, __LINE__
            );

            if (!close_and_clear(epoll_descriptor)) {
                pop(epoll_descriptor);
            }

            return NO_DESCRIPTOR;
        }

        epoll_event *event = &(record.events[0]);

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

        set_flag(epoll_descriptor, FLAG::EPOLL);

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
                make_record(descriptor, NO_DESCRIPTOR)
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

            record_type record{pop(descriptor)};
            bool found = record.descriptor != NO_DESCRIPTOR;

            int close_children_of = NO_DESCRIPTOR;

            if (record.parent == NO_DESCRIPTOR) {
                close_children_of = descriptor;
            }

            if (!found) {
                log(
                    logfrom.c_str(),
                    "descriptor %d closed but record not found (%s:%d)",
                    descriptor, __FILE__, __LINE__
                );
            }

            if (close_children_of != NO_DESCRIPTOR) {
                std::vector<int> to_be_closed;

                for (size_t key=0; key<descriptors.size(); ++key) {
                    for (size_t i=0, sz=descriptors[key].size(); i<sz; ++i) {
                        const record_type &rec = descriptors[key][i];

                        if (rec.parent != close_children_of) {
                            continue;
                        }

                        to_be_closed.emplace_back(rec.descriptor);
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
                            record = pop(d);

                            if (record.descriptor == NO_DESCRIPTOR) {
                                log(
                                    logfrom.c_str(),
                                    "descriptor %d closed but record not found "
                                    "(%s:%d)", d, __FILE__, __LINE__
                                );
                            }

                            ++closed;
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

    inline record_type pop(int descriptor) {
        if (descriptor == NO_DESCRIPTOR) {
            return make_record(NO_DESCRIPTOR, NO_DESCRIPTOR);
        }

        size_t key_hash = descriptor % descriptors.size();

        for (size_t i=0, sz=descriptors[key_hash].size(); i<sz; ++i) {
            const record_type &rec = descriptors[key_hash][i];

            if (rec.descriptor != descriptor) continue;

            int parent_descriptor = rec.parent;

            // First, let's free the flags.
            for (size_t j=0, fsz=flags.size(); j<fsz; ++j) {
                rem_flag(rec.descriptor, static_cast<FLAG>(j));
            }

            // Then, we free the events.
            if (rec.events) {
                delete [] rec.events;
            }

            // Finally, we remove the record.
            descriptors[key_hash][i] = descriptors[key_hash].back();
            descriptors[key_hash].pop_back();

            return make_record(descriptor, parent_descriptor);
        }

        return make_record(NO_DESCRIPTOR, NO_DESCRIPTOR);
    }

    inline const record_type *find_record(int descriptor) const {
        size_t key = descriptor % descriptors.size();

        for (size_t i=0, sz=descriptors.at(key).size(); i<sz; ++i) {
            if (descriptors.at(key).at(i).descriptor != descriptor) continue;

            return &(descriptors.at(key).at(i));
        }

        return nullptr;
    }

    inline record_type *find_record(int descriptor) {
        return const_cast<record_type *>(
            static_cast<const SOCKETS &>(*this).find_record(descriptor)
        );
    }

    inline bool is_listener(int descriptor) {
        record_type *rec = find_record(descriptor);
        return rec && rec->parent == NO_DESCRIPTOR;
    }

    bool set_flag(int descriptor, FLAG flag) {
        size_t index = static_cast<size_t>(flag);

        if (index > flags.size()) {
            return false;
        }

        record_type *rec = find_record(descriptor);

        if (!rec) return false;

        uint32_t pos = rec->flags[index];

        if (pos == std::numeric_limits<uint32_t>::max()) {
            if (flags[index].size() < std::numeric_limits<uint32_t>::max()) {
                rec->flags[index] = uint32_t(flags[index].size());
                flags[index].emplace_back(make_flag(descriptor, flag));
            }
            else {
                log(
                    logfrom.c_str(), "flag buffer is full (%s:%d)",
                    __FILE__, __LINE__
                );

                return false;
            }
        }

        return true;
    }

    bool rem_flag(int descriptor, FLAG flag) {
        size_t index = static_cast<size_t>(flag);

        if (index > flags.size()) {
            return false;
        }

        record_type *rec = find_record(descriptor);

        if (!rec) return false;

        uint32_t pos = rec->flags[index];

        if (pos != std::numeric_limits<uint32_t>::max()) {
            flags[index][pos] = flags[index].back();

            int other_descriptor = flags[index].back().descriptor;
            find_record(other_descriptor)->flags[index] = pos;

            flags[index].pop_back();
            rec->flags[index] = std::numeric_limits<uint32_t>::max();
        }

        return true;
    }

    bool has_flag(int descriptor, FLAG flag) {
        size_t index = static_cast<size_t>(flag);

        if (index > flags.size()) {
            return false;
        }

        record_type *rec = find_record(descriptor);

        if (!rec) return false;

        uint32_t pos = rec->flags[index];

        if (pos != std::numeric_limits<uint32_t>::max()) {
            return true;
        }

        return false;
    }

    std::string logfrom;
    void (*log)(const char *, const char *p_fmt, ...);
    std::array<std::vector<record_type>, 1024> descriptors;
    std::array<
        std::vector<flag_type>,
        static_cast<size_t>(FLAG::MAX_FLAGS)
    > flags;
    sigset_t sigset_all;
    sigset_t sigset_none;
    sigset_t sigset_orig;
};

#endif
