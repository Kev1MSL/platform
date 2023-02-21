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
    icmp_analyzer_packet(const uint8_t *raw_data, int raw_data_len, timespec timestamp);

    icmp_analyzer_packet();

    uint8_t get_byte_from_packet(int offset);

    std::vector<uint8_t>
    get_bytes_from_packet(int begin_offset, int end_offset);

    std::string print_time_captured();

    std::string print_time_icmp_sent();

    bool is_icmp_packet();

    [[nodiscard]] icmp_type get_icmp_type() const;

    [[nodiscard]] int get_signal_strength() const;

    [[nodiscard]] int get_sequence_number() const;

    [[nodiscard]] int get_id_number() const;

    [[nodiscard]] uint32_t get_wlan_duration() const;

    [[nodiscard]] std::chrono::duration<long, std::ratio<1, 1000000000>> get_sent_time() const;

    [[nodiscard]] std::chrono::duration<long, std::ratio<1, 1000000000>> get_captured_time() const;


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

    size_t get_packet_count();

    std::pair<icmp_analyzer_packet, icmp_analyzer_packet> get_icmp_req_rep(int sequence_number);

    std::vector<std::pair<icmp_analyzer_packet, icmp_analyzer_packet>> get_icmp_req_rep_list();


    ~icmp_analyzer_adapter();

private:
    std::vector<icmp_analyzer_packet> icmp_packet_list;
};


#endif //PLATFORM_ICMP_ANALYZER_H
