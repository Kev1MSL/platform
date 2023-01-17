//
// Created by Kevin on 17/01/2023.
//

#ifndef PLATFORM_SETUP_AD_HOC_H
#define PLATFORM_SETUP_AD_HOC_H

#include <iostream>
#include <fstream>
#include <unistd.h>

void setup_ad_hoc(const std::string& ssid, const std::string& ip, const std::string& channel);
bool check_setup_already_done(std::ofstream &adhoc_file);

#endif //PLATFORM_SETUP_AD_HOC_H
