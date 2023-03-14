//
// Created by Kevin on 18/01/2023.
//

#include "config.h"

void change_tx_power(const std::string &tx_power)
{
    std::string command = "sudo iw dev wlan0 set txpower " + tx_power;
    system(command.c_str());
    std::cout << "TX Power changed to " << tx_power << "dBm" << std::endl;
}

void change_rate(const std::string &rate)
{
    // iw dev wlan0 set birates
    std::string command = "sudo iwconfig wlan0 rate " + rate;
    system(command.c_str());
    std::cout << "Rate changed to " << rate << "Mb/s" << std::endl;
}

void change_sensitivity(const std::string &sensitivity)
{
    std::string command = "sudo iwconfig wlan0 sens " + sensitivity;
    system(command.c_str());
    std::cout << "Threshold sensitivity changed to " << sensitivity << std::endl;
}

void change_channel(const std::string &channel)
{
    std::string command = "sudo iw wlan0 channel " + channel;
    system(command.c_str());
    std::cout << "Channel changed to " << channel << std::endl;
}

void change_bandwidth(int channel, const std::string &bandwidth)
{
    std::string command = "sudo iw set channel " + std::to_string(channel) + bandwidth;
    system(command.c_str());
    std::cout << "Bandwidth changed to " << bandwidth << std::endl;
}

void turn_off_interface(const std::string &interface)
{
    std::string command = "sudo ifconfig " + interface + " down";
    system(command.c_str());
    std::cout << "Interface " << interface << " turned off" << std::endl;
}

void turn_on_interface(const std::string &interface)
{
    std::string command = "sudo ifconfig " + interface + " up";
    system(command.c_str());
    std::cout << "Interface " << interface << " turned on" << std::endl;
}