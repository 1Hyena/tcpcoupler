#ifndef PROGRAM_H_01_01_2021
#define PROGRAM_H_01_01_2021

#include <string>

class PROGRAM {
    public:

    PROGRAM(
        const char *name,
        const char *version)
    : pname(name)
    , pver(version)
    , status(EXIT_FAILURE)
    , options(nullptr)
    , max_sys_cmd_len(0) {}

    ~PROGRAM() {}

    static size_t get_log_size();

    static void log(
        const char *, const char *, ...
    ) __attribute__((format(printf, 2, 3)));

    void bug(const char * =__builtin_FILE(), int =__builtin_LINE());
    bool init(int argc, char **argv);
    void run();
    int deinit();
    int get_status() const;

    const char *get_name() const;
    const char *get_version() const;
    const char *get_comment() const;
    uint16_t get_supply_port() const;
    uint16_t get_demand_port() const;

    private:

    std::string    pname;
    std::string    pver;
    int            status;
    class OPTIONS *options;
    std::string    comment;
    size_t         max_sys_cmd_len;

    static size_t log_size;
};

#endif
