//
// Created by kevin on 16/02/23.
//

#ifndef PLATFORM_PACKET_ANALYZER_H
#define PLATFORM_PACKET_ANALYZER_H

#include <iostream>
#include <cstdlib>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <string>
#include <vector>
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/SystemUtils.h"
#include "pcapplusplus/IcmpLayer.h"
#include <tuple>
#include "icmp_analyzer.h"

#define IS_MONITOR_MODE 1

class packet_analyzer
{
public:
    packet_analyzer(const std::string &device_name);

    void print_device_info();

    void start_capture();

    void stop_capture();

    void parse_packets();

    ~packet_analyzer();

private:
    pcpp::PcapLiveDevice *m_device;
    pcpp::RawPacketVector packet_vector;
    std::vector<std::tuple<std::chrono::duration<long, std::ratio<1, 1000000000>>, std::chrono::duration<long, std::ratio<1, 1000000000>>>> icmp_packet_timestamps;

    static std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType);

/*    static uint8_t get_byte_from_packet(const uint8_t *data, int max_length, int offset);

    static std::vector<uint8_t>
    get_bytes_from_packet(const uint8_t *data, int max_length, int begin_offset, int end_offset);*/
};

#endif // PLATFORM_PACKET_ANALYZER_H
