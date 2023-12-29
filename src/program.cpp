// SPDX-License-Identifier: MIT
#include <iostream>
#include <stdarg.h>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <vector>

#include "options.h"
#include "program.h"
#include "signals.h"
#include "sockets.h"

volatile sig_atomic_t
    SIGNALS::sig_alarm{0},
    SIGNALS::sig_pipe {0},
    SIGNALS::sig_int  {0},
    SIGNALS::sig_term {0},
    SIGNALS::sig_quit {0};

size_t PROGRAM::log_size = 0;
bool   PROGRAM::log_time = false;

void PROGRAM::run() {
    static constexpr const char
        *ansi_G = "\x1B[1;32m",
        *ansi_R = "\x1B[1;31m",
        *ansi_B = "\x1B[1;34m",
        *ansi_x = "\x1B[0m";

    if (!options) return bug();

    if (options->exit_flag) {
        status = EXIT_SUCCESS;
        return;
    }

    sockets->set_logger(
        [](SOCKETS::SESSION session, const char *text) noexcept {
            std::string line;
            char time[20];

            write_time(time, sizeof(time));
            line.append(time).append(" :: ");

            if (!session) {
                line.append("Sockets: ");
            }
            else {
                char buffer[20];
                std::snprintf(buffer, 20, "#%06lx: ", session.id);
                line.append(buffer);
            }

            const char *esc = "\x1B[0;31m";

            switch (session.error) {
                case SOCKETS::BAD_TIMING:    esc = "\x1B[1;33m"; break;
                case SOCKETS::LIBRARY_ERROR: esc = "\x1B[1;31m"; break;
                case SOCKETS::NO_ERROR:      esc = "\x1B[0;32m"; break;
                default: break;
            }

            line.append(esc).append(text).append("\x1B[0m").append("\n");
            print_text(stderr, line.c_str(), line.size());
        }
    );

    bool terminated = false;

    SOCKETS::SESSION supply_session{
        sockets->listen(std::to_string(get_supply_port()).c_str())
    };

    SOCKETS::SESSION demand_session{
        sockets->listen(std::to_string(get_demand_port()).c_str())
    };

    SOCKETS::SESSION driver_session{};

    if (get_driver_port()) {
        driver_session = sockets->listen(
            std::to_string(get_driver_port()).c_str()
        );
    }

    if (!supply_session
    ||  !demand_session) {
        terminated = true;
        status = EXIT_FAILURE;
    }
    else {
        status = EXIT_SUCCESS;
        log_time = true;

        if (!driver_session) {
            log(
                "Listening on ports %d and %d...",
                int(get_supply_port()), int(get_demand_port())
            );
        }
        else {
            log(
                "Listening on ports %d, %d and %d...",
                int(get_supply_port()), int(get_demand_port()),
                int(get_driver_port())
            );
        }
    }

    std::unordered_map<size_t, long long> timestamp_map;
    std::unordered_map<size_t, size_t> supply_map;
    std::unordered_map<size_t, size_t> demand_map;
    std::unordered_set<size_t> unmet_supply;
    std::unordered_set<size_t> unmet_demand;
    std::unordered_set<size_t> drivers;

    static constexpr const size_t USEC_PER_SEC = 1000000;
    bool alarmed = false;
    set_timer(USEC_PER_SEC);

    do {
        alarmed = false;

        signals->block();
        while (int sig = signals->next()) {
            char *sig_name = strsignal(sig);

            switch (sig) {
                case SIGALRM: {
                    alarmed = true;
                    break;
                }
                case SIGINT :
                case SIGTERM:
                case SIGQUIT: {
                    terminated = true;
                    [[fallthrough]];
                }
                default     : {
                    // Since signals are blocked, we can call fprintf here.
                    fprintf(stderr, "%s", "\n");

                    log(
                        "Caught signal %d (%s).", sig,
                        sig_name ? sig_name : "unknown"
                    );

                    break;
                }
            }
        }

        if (alarmed) set_timer(USEC_PER_SEC);

        signals->unblock();

        if (terminated) {
            sockets->disconnect(demand_session.id);
            sockets->disconnect(supply_session.id);
            sockets->disconnect(driver_session.id);

            continue;
        }

        if (!alarmed && sockets->next_error() != SOCKETS::NO_ERROR) {
            log("Sockets: %s", sockets->to_string(sockets->last_error()));
            status = EXIT_FAILURE;
            terminated = true;
        }

        long long timestamp = get_timestamp();
        size_t new_demand = 0;
        SOCKETS::ALERT alert;

        while ((alert = sockets->next_alert()).valid) {
            const size_t sid = alert.session;
            size_t other = 0;

            if (alert.event == SOCKETS::DISCONNECTION) {
                log(
                    "Session %s#%06lx%s@%s:%s disconnected.",
                    supply_map.count(sid) || unmet_supply.count(sid) ? ansi_G :
                    demand_map.count(sid) || unmet_demand.count(sid) ? ansi_R :
                    drivers.count(sid)    ? ansi_B : ansi_x,
                    sid, ansi_x, sockets->get_host(sid), sockets->get_port(sid)
                );

                if (timestamp_map.count(sid)) {
                    timestamp_map.erase(sid);
                }

                if (drivers.count(sid)) {
                    drivers.erase(sid);
                    continue;
                }

                if (supply_map.count(sid)) {
                    other = supply_map[sid];
                    supply_map.erase(sid);
                }
                else if (demand_map.count(sid)) {
                    other = demand_map[sid];
                    demand_map.erase(sid);
                }
                else {
                    unmet_supply.erase(sid);
                    unmet_demand.erase(sid);
                }

                if (other) {
                    if (supply_map.count(other)) {
                        supply_map[other] = 0;
                    }
                    else if (demand_map.count(other)) {
                        demand_map[other] = 0;
                    }

                    sockets->disconnect(other);
                }
            }
            else if (alert.event == SOCKETS::CONNECTION) {
                timestamp_map[sid] = timestamp;

                SOCKETS::SESSION listener = sockets->get_listener(sid);

                if (listener.id == supply_session.id) {
                    if (unmet_demand.empty()) {
                        unmet_supply.insert(sid);
                        sockets->freeze(sid);
                    }
                    else {
                        other = *(unmet_demand.begin());
                        unmet_demand.erase(other);
                        supply_map[sid] = other;
                        demand_map[other] = sid;
                        sockets->unfreeze(other);
                        timestamp_map[other] = timestamp;
                    }
                }
                else if (listener.id == demand_session.id) {
                    if (unmet_supply.empty()) {
                        unmet_demand.insert(sid);
                        sockets->freeze(sid);
                        ++new_demand;
                    }
                    else {
                        other = *(unmet_supply.begin());
                        unmet_supply.erase(other);
                        demand_map[sid] = other;
                        supply_map[other] = sid;
                        sockets->unfreeze(other);
                        timestamp_map[other] = timestamp;
                    }
                }
                else if (listener.id == driver_session.id && !!driver_session) {
                    drivers.insert(sid);

                    timestamp_map[sid] = (
                        // Kludge to skip reporting new demand to this driver.
                        timestamp + 1LL
                    );

                    SOCKETS::ERROR error{
                        sockets->writef(sid, "%lu\n", unmet_demand.size())
                    };

                    if (error != SOCKETS::NO_ERROR) {
                        log(
                            "%s (%s:%d)", sockets->to_string(error),
                            __FILE__, __LINE__
                        );
                    }
                }
                else {
                    log("Forbidden condition met (%s:%d).", __FILE__, __LINE__);
                }

                log(
                    "Session %s#%06lx%s@%s:%s connected.",
                    supply_map.count(sid) || unmet_supply.count(sid) ? ansi_G :
                    demand_map.count(sid) || unmet_demand.count(sid) ? ansi_R :
                    drivers.count(sid)    ? ansi_B : ansi_x,
                    sid, ansi_x, sockets->get_host(sid), sockets->get_port(sid)
                );
            }
            else if (alert.event == SOCKETS::INCOMING) {
                if (!drivers.count(sid)) {
                    size_t forward_to = 0;

                    if (supply_map.count(sid)) {
                        forward_to = supply_map[sid];
                    }
                    else if (demand_map.count(sid)) {
                        forward_to = demand_map[sid];
                    }

                    if (!forward_to) {
                        log(
                            "Forbidden condition met (%s:%d).",
                            __FILE__, __LINE__
                        );
                    }
                    else {
                        const size_t size = sockets->get_incoming_size(sid);
                        const char *data = sockets->peek(sid);

                        if (!sockets->write(forward_to, data, size)) {
                            sockets->read(sid);
                            timestamp_map[sid] = timestamp;
                            timestamp_map[forward_to] = timestamp;

                            if (is_verbose()) {
                                log(
                                    "%lu byte%s from %s#%06lx%s %s sent to "
                                    "%s#%06lx%s.",
                                    size, size == 1 ? "" : "s",
                                    supply_map.count(sid) ? ansi_G : ansi_R,
                                    sid, ansi_x,
                                    size == 1 ? "is" : "are",
                                    supply_map.count(forward_to) ? (
                                        ansi_G
                                    ) : ansi_R, forward_to, ansi_x
                                );
                            }
                        }
                        else {
                            log(
                                "Failed to send %lu byte%s from %s#%06lx%s to "
                                "%s#%06lx%s.",
                                size, size == 1 ? "" : "s",
                                supply_map.count(sid) ? ansi_G : ansi_R, sid,
                                ansi_x,
                                supply_map.count(forward_to) ? ansi_G : ansi_R,
                                forward_to, ansi_x
                            );

                            sockets->disconnect(forward_to);
                            sockets->disconnect(sid);
                        }
                    }
                }
                else {
                    sockets->read(sid);
                    timestamp_map[sid] = timestamp;
                }
            }
        }

        if (new_demand || alarmed) {
            for (size_t driver : drivers) {
                if (timestamp_map[driver] > timestamp) {
                    // This is a brand new driver and thus it must have already
                    // received the current number of unmet demand.

                    timestamp_map[driver] = timestamp;
                    continue;
                }

                if (!new_demand) {
                    uint32_t driver_period = get_driver_period();

                    if (!driver_period
                    ||  timestamp - timestamp_map[driver] < driver_period) {
                        continue;
                    }

                    SOCKETS::ERROR error{
                        sockets->writef(driver, "%lu\n", unmet_demand.size())
                    };

                    if (error != SOCKETS::NO_ERROR) {
                        log(
                            "%s (%s:%d)", sockets->to_string(error),
                            __FILE__, __LINE__
                        );
                    }
                }
                else {
                    SOCKETS::ERROR error{
                        sockets->writef(driver, "%lu\n", new_demand)
                    };

                    if (error != SOCKETS::NO_ERROR) {
                        log(
                            "%s (%s:%d)", sockets->to_string(error),
                            __FILE__, __LINE__
                        );
                    }
                }

                timestamp_map[driver] = timestamp;
            }
        }

        uint32_t idle_timeout = get_idle_timeout();

        if (idle_timeout > 0 && alarmed) {
            for (const auto &p : timestamp_map) {
                if (timestamp - p.second >= idle_timeout) {
                    size_t sid = p.first;

                    if (is_verbose()) {
                        log(
                            "Session %s#%06lx%s@%s:%s has timed out.",
                            supply_map.count(sid) ? ansi_G :
                            demand_map.count(sid) ? ansi_R :
                            drivers.count(sid)    ? ansi_B : ansi_x,
                            sid, ansi_x,
                            sockets->get_host(sid), sockets->get_port(sid)
                        );
                    }

                    sockets->disconnect(sid);
                }
            }
        }
    }
    while (!terminated);

    return;
}

bool PROGRAM::init(int argc, char **argv) {
    signals = new (std::nothrow) SIGNALS(print_log);
    if (!signals) return false;

    if (!signals->init()) {
        return false;
    }

    options = new (std::nothrow) OPTIONS(get_version(), print_log);
    if (!options) return false;

    if (!options->init(argc, argv)) {
        return false;
    }

    sockets = new (std::nothrow) SOCKETS();
    if (!sockets) return false;

    return sockets->init();
}

int PROGRAM::deinit() {
    if (sockets) {
        if (!sockets->deinit()) {
            status = EXIT_FAILURE;
            bug();
        }

        delete sockets;
        sockets = nullptr;
    }

    if (options) {
        delete options;
        options = nullptr;
    }

    if (signals) {
        delete signals;
        signals = nullptr;
    }

    return get_status();
}

int PROGRAM::get_status() const {
    return status;
}

size_t PROGRAM::get_log_size() {
    return PROGRAM::log_size;
}

void PROGRAM::write_time(char *buffer, size_t length) {
    struct timeval timeofday;
    gettimeofday(&timeofday, nullptr);

    time_t timestamp = (time_t) timeofday.tv_sec;
    struct tm *tm_ptr = gmtime(&timestamp);

    if (!strftime(buffer, length, "%Y-%m-%d %H:%M:%S", tm_ptr)) {
        buffer[0] = '\0';
    }
}

bool PROGRAM::print_text(FILE *fp, const char *text, size_t len) {
    // Because fwrite may be interrupted by a signal, we block them.

    sigset_t sigset_all;
    sigset_t sigset_orig;

    if (sigfillset(&sigset_all) == -1) {
        return false;
    }
    else if (sigprocmask(SIG_SETMASK, &sigset_all, &sigset_orig) == -1) {
        return false;
    }

    fwrite(text , sizeof(char), len, fp);

    if (sigprocmask(SIG_SETMASK, &sigset_orig, nullptr) == -1) {
        return false;
    }

    return true;
}

void PROGRAM::print_log(const char *origin, const char *p_fmt, ...) {
    va_list ap;
    char *buf = nullptr;
    char *newbuf = nullptr;
    int buffered = 0;
    int	size = 1024;

    if (p_fmt == nullptr) return;
    buf = (char *) malloc (size * sizeof (char));

    while (1) {
        va_start(ap, p_fmt);
        buffered = vsnprintf(buf, size, p_fmt, ap);
        va_end (ap);

        if (buffered > -1 && buffered < size) break;
        if (buffered > -1) size = buffered + 1;
        else               size *= 2;

        if ((newbuf = (char *) realloc (buf, size)) == nullptr) {
            free (buf);
            return;
        } else {
            buf = newbuf;
        }
    }

    std::string logline;
    logline.reserve(size);

    if (PROGRAM::log_time) {
        char timebuf[20];
        struct timeval timeofday;
        gettimeofday(&timeofday, nullptr);

        time_t timestamp = (time_t) timeofday.tv_sec;
        struct tm *tm_ptr = gmtime(&timestamp);

        if (!strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_ptr)) {
            timebuf[0] = '\0';
        }

        logline.append(timebuf);
        logline.append(" :: ");
    }

    if (origin && *origin) {
        logline.append(origin);
        logline.append(": ");
    }

    logline.append(buf);

    if (origin) logline.append("\n");

    PROGRAM::log_size += logline.size();
    print_text(stderr, logline.c_str(), logline.size());
    free(buf);
}

void PROGRAM::log(const char *p_fmt, ...) {
    va_list ap;
    char *buf = nullptr;
    char *newbuf = nullptr;
    int buffered = 0;
    int	size = 1024;

    if (p_fmt == nullptr) return;
    buf = (char *) malloc (size * sizeof (char));

    while (1) {
        va_start(ap, p_fmt);
        buffered = vsnprintf(buf, size, p_fmt, ap);
        va_end (ap);

        if (buffered > -1 && buffered < size) break;
        if (buffered > -1) size = buffered + 1;
        else               size *= 2;

        if ((newbuf = (char *) realloc (buf, size)) == nullptr) {
            free (buf);
            return;
        } else {
            buf = newbuf;
        }
    }

    print_log("", "%s", buf);
    free(buf);
}

void PROGRAM::bug(const char *file, int line) {
    log("Bug on line %d of %s.", line, file);
}

const char *PROGRAM::get_name() const {
    return pname.c_str();
}

const char *PROGRAM::get_version() const {
    return pver.c_str();
}

uint16_t PROGRAM::get_supply_port() const {
    return options->supply_port;
}

uint16_t PROGRAM::get_demand_port() const {
    return options->demand_port;
}

uint16_t PROGRAM::get_driver_port() const {
    return options->driver_port;
}

bool PROGRAM::is_verbose() const {
    return options->verbose;
}

uint32_t PROGRAM::get_idle_timeout() const {
    return options->idle_timeout;
}

uint32_t PROGRAM::get_driver_period() const {
    return options->driver_period;
}

void PROGRAM::set_timer(size_t usec) {
    timer.it_value.tv_sec     = usec / 1000000;
    timer.it_value.tv_usec    = usec % 1000000;
    timer.it_interval.tv_sec  = 0;
    timer.it_interval.tv_usec = 0;

    setitimer(ITIMER_REAL, &timer, nullptr);
}

long long PROGRAM::get_timestamp() const {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}
