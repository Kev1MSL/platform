#ifndef TOOLS_PROPAGATE_UPDATE_PROPAGATE_UPDATE
#define TOOLS_PROPAGATE_UPDATE_PROPAGATE_UPDATE

#include <iostream>
#include <filesystem>
#include <libssh/libssh.h>
#include <stdlib.h>
#include <jsoncpp/json/json.h>
#include <jsoncpp/json/value.h>
#include <sys/stat.h>

#define PATH "/home/pi/Documents/Kevin_Bachelor_Thesis"

/// @brief Struct to hold the SSH configuration.
typedef struct
{
    std::string host;
    std::string username;
    std::string password;
    std::string path;
} ssh_config;

/// @brief Class to do operations such as sending files, running commands, etc. on a remote machine through SSH.
class ssh_updater
{
private:
    ssh_session session;
    std::string host;

    std::vector<std::string> split_dir(const std::string &path);

public:
    ssh_updater(ssh_config &config);

    int run_update(const std::string &path);

    int run_command(const std::string &command);

    int install_packages(const std::vector<std::string> &packages);

    int
    send_files(const std::string &from_path, const std::string &target_path, const std::vector<std::string> &filenames);

    int start_monitor(bool icmp_only);

    int stop_monitor();

    int download_file(const std::string &from_path, const std::string &target_path);

    void disconnect();

    ~ssh_updater();

    int set_ntp_server(const std::string &ntp_server);
};

void add_files_from_dir(std::vector<std::string> *files, const std::string &path);

#endif /* TOOLS_PROPAGATE_UPDATE_PROPAGATE_UPDATE */
