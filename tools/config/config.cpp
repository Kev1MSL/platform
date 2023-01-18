//
// Created by Kevin on 18/01/2023.
//

#include "config.h"

void change_tx_power(const std::string &tx_power) {
    std::string command = "sudo iwconfig wlan0 txpower " + tx_power;
    system(command.c_str());
    std::cout << "TX Power changed to " << tx_power << "dBm" << std::endl;
}

void change_rate(const std::string &rate) {
    std::string command = "sudo iwconfig wlan0 rate " + rate;
    system(command.c_str());
    std::cout << "Rate changed to " << rate << "Mb/s" << std::endl;
}

void change_sensitivity(const std::string &sensitivity) {
    std::string command = "sudo iwconfig wlan0 sens " + sensitivity;
    system(command.c_str());
    std::cout << "Threshold sensitivity changed to " << sensitivity << std::endl;
}
