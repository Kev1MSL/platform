//
// Created by Kevin Messali on 20/02/23.
//

#ifndef PLATFORM_ICMP_ANALYZER_H
#define PLATFORM_ICMP_ANALYZER_H

#include <cstdlib>
#include <chrono>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

enum icmp_type
{
    ICMP_REQUEST,
    ICMP_REPLY,
    NOT_ICMP
};

class icmp_analyzer_packet
{
public:
    icmp_analyzer_packet(const uint8_t *raw_data, int raw_data_len, timespec captured_tv_sec,
                         timespec captured_tv_nsec);

    uint8_t get_byte_from_packet(int offset);

    std::vector<uint8_t>
    get_bytes_from_packet(int begin_offset, int end_offset);

    std::string print_time_captured();

    std::string print_time_icmp_sent();

private:
    icmp_type icmpType;
    int signal_strength;
    int sequence_number;
    int id_number;
    std::chrono::duration<long, std::ratio<1, 1000000000>> sent_time{};
    std::chrono::duration<long, std::ratio<1, 1000000000>> captured_time{};
    uint32_t wlan_duration;
    const uint8_t *raw_data;
    int raw_data_len;
};

class icmp_analyzer_adapter
{
public:
    icmp_analyzer_adapter(const icmp_analyzer_packet &icmp_packet);

    icmp_analyzer_adapter();

    void add_icmp_packet(const icmp_analyzer_packet &icmp_packet);

    ~icmp_analyzer_adapter();

private:
    std::vector<icmp_analyzer_packet> icmp_packet_list;
};


#endif //PLATFORM_ICMP_ANALYZER_H
