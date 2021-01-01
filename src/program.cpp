#include <iostream>
#include <stdarg.h>

#include "options.h"
#include "program.h"

size_t PROGRAM::log_size = 0;

void PROGRAM::run() {
    if (!options) return bug();

    if (options->exit_flag) {
        status = EXIT_SUCCESS;
        return;
    }

    log(
        get_name(), "Listening on ports %d and %d.",
        int(get_supply_port()), int(get_demand_port())
    );

    status = EXIT_SUCCESS;
    return;
}

bool PROGRAM::init(int argc, char **argv) {
    options = new (std::nothrow) OPTIONS(get_version(), log);
    if (!options) return false;

    if (!options->init(argc, argv)) {
        return false;
    }

    return true;
}

int PROGRAM::deinit() {
    if (options) {
        delete options;
        options = nullptr;
    }

    return get_status();
}

int PROGRAM::get_status() const {
    return status;
}

size_t PROGRAM::get_log_size() {
    return PROGRAM::log_size;
}

void PROGRAM::log(const char *origin, const char *p_fmt, ...) {
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

    std::string logline(origin);
    logline.reserve(size);
    logline.append(": ").append(buf).append("\n");

    PROGRAM::log_size += logline.size();
    std::cerr << logline;
    free(buf);
}

void PROGRAM::bug(const char *file, int line) {
    if (comment.empty()) {
        log(get_name(), "Bug on line %d of %s.", line, file);
        return;
    }

    log(get_name(), "%s: Bug on line %d of %s.", comment.c_str(), line, file);
}

const char *PROGRAM::get_name() const {
    return pname.c_str();
}

const char *PROGRAM::get_version() const {
    return pver.c_str();
}

const char *PROGRAM::get_comment() const {
    return comment.c_str();
}

uint16_t PROGRAM::get_supply_port() const {
    return options->supply_port;
}

uint16_t PROGRAM::get_demand_port() const {
    return options->demand_port;
}
