//
// Created by Kevin on 31/01/2023.
//

#include "set_monitor_mode.h"

void set_monitor_mode(const std::string &iface)
{
    std::string cmd = "sudo ifconfig " + iface + " down";
    system(cmd.c_str());
    cmd = "sudo iwconfig " + iface + " mode monitor";
    system(cmd.c_str());
    cmd = "sudo ifconfig " + iface + " up";
    system(cmd.c_str());
    cmd = "sudo iwconfig " + iface + " channel 1";
    system(cmd.c_str());
}
