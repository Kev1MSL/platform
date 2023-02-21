//
// Created by Kevin Messali on 19/02/23.
//

#ifndef PLATFORM_PACKET_ANALYZER_TINS_H
#define PLATFORM_PACKET_ANALYZER_TINS_H

#include <iostream>
#include <string>
#include <tins/tins.h>

class packet_analyzer_tins
{
public:
    packet_analyzer_tins(const std::string &device_name);

    void print_device_info();

    void start_capture();

    void stop_capture();

    void parse_packets();

    ~packet_analyzer_tins();

private:
/*    Tins::SnifferConfiguration config;
    Tins::Sniffer sniffer;*/
};


#endif //PLATFORM_PACKET_ANALYZER_TINS_H
