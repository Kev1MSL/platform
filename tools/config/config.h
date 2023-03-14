//
// Created by Kevin on 18/01/2023.
//

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <iostream>
#include <string>

void change_tx_power(const std::string &tx_power);

void change_rate(const std::string &rate);

void change_sensitivity(const std::string &sensitivity);

void change_channel(const std::string &channel);

void change_bandwidth(int channel, const std::string &bandwidth);

void turn_off_interface(const std::string &interface);

void turn_on_interface(const std::string &interface);

#endif //PLATFORM_CONFIG_H
