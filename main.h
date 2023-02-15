//
// Created by Kevin on 17/01/2023.
//

#ifndef MAIN
#define MAIN

#include <iostream>
#include <fstream>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "cxxopts.hpp"
#include "tools/setup_ad_hoc/setup_ad_hoc.h"
#include "tools/reset_ad_hoc/reset_ad_hoc.h"
#include "tools/set_monitor_mode/set_monitor_mode.h"
#include "tools/config/config.h"
#include "tools/propagate_update/propagate_update.h"

std::vector<ssh_config> get_ssh_config(const std::string &path = PATH);
std::string get_ip_address(const std::string &iface);
std::vector<std::string> split(const std::string &str);
void add_files_from_dir(std::vector<std::string> *files, const std::string &path);

#endif /* MAIN */
