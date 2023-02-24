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
    ICMP_ECHO_REQUEST = 0x8,
    ICMP_ECHO_REPLY = 0x0,
    ICMP_TIMESTAMP_REQUEST = 0xd,
    ICMP_TIMESTAMP_REPLY = 0xe,
    NOT_ICMP
};

// TODO: Make a general class for monitoring packet and inherit from it
class icmp_echo_analyzer_monitor_packet
{
public:
    icmp_echo_analyzer_monitor_packet(const uint8_t *raw_data, int raw_data_len, timespec timestamp);

    icmp_echo_analyzer_monitor_packet();

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

    [[nodiscard]] int get_data_len() const;

    void set_sent_time(std::chrono::duration<long, std::ratio<1, 1000000000>> time);

    void set_captured_time(std::chrono::duration<long, std::ratio<1, 1000000000>> time);


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


class icmp_echo_analyzer_adapter
{
public:

    icmp_echo_analyzer_adapter();

    void add_icmp_packet(const icmp_echo_analyzer_monitor_packet &icmp_packet);

    size_t get_packet_count();

    std::pair<icmp_echo_analyzer_monitor_packet, icmp_echo_analyzer_monitor_packet>
    get_icmp_req_rep(int sequence_number);

    std::vector<std::pair<icmp_echo_analyzer_monitor_packet, icmp_echo_analyzer_monitor_packet>>
    get_icmp_req_rep_list();

    void change_echo_icmp_req_rep_time(int id_number, int sequence_number,
                                       std::chrono::duration<long, std::ratio<1, 1000000000>> time);

    void change_echo_icmp_captured_time(icmp_type type, int id_number, int sequence_number,
                                        std::chrono::duration<long, std::ratio<1, 1000000000>> time);

    ~icmp_echo_analyzer_adapter();

private:
    std::vector<icmp_echo_analyzer_monitor_packet> icmp_packet_list;
};


class icmp_timestamp_analyzer_monitor_packet
{
public:
    icmp_timestamp_analyzer_monitor_packet(const uint8_t *raw_data, int raw_data_len, timespec timestamp);

    icmp_timestamp_analyzer_monitor_packet();

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

    [[nodiscard]] std::chrono::duration<long, std::ratio<1, 1000000000>> get_orig_ts() const;

    [[nodiscard]] std::chrono::duration<long, std::ratio<1, 1000000000>> get_received_ts() const;

    [[nodiscard]] std::chrono::duration<long, std::ratio<1, 1000000000>> get_transmit_ts() const;

    [[nodiscard]] std::chrono::duration<long, std::ratio<1, 1000000000>> get_captured_time() const;

    [[nodiscard]] int get_data_len() const;

    void set_orig_ts(std::chrono::duration<long, std::ratio<1, 1000000000>> time);

    void set_received_ts(std::chrono::duration<long, std::ratio<1, 1000000000>> time);

    void set_transmit_ts(std::chrono::duration<long, std::ratio<1, 1000000000>> time);

    void set_captured_time(std::chrono::duration<long, std::ratio<1, 1000000000>> time);


private:
    icmp_type icmpType;
    int signal_strength;
    int sequence_number;
    int id_number;
    std::chrono::duration<long, std::ratio<1, 1000000000>> orig_ts{};
    std::chrono::duration<long, std::ratio<1, 1000000000>> received_ts{};
    std::chrono::duration<long, std::ratio<1, 1000000000>> transmit_ts{};
    std::chrono::duration<long, std::ratio<1, 1000000000>> captured_time{};
    uint32_t wlan_duration;
    const uint8_t *raw_data;
    int raw_data_len;
};

class icmp_timestamp_analyzer_adapter
{
public:

    icmp_timestamp_analyzer_adapter();

    void add_icmp_packet(const icmp_timestamp_analyzer_monitor_packet &icmp_packet);

    std::pair<icmp_timestamp_analyzer_monitor_packet, icmp_timestamp_analyzer_monitor_packet>
    get_icmp_ts_req_rep(int sequence_number);

    std::vector<std::pair<icmp_timestamp_analyzer_monitor_packet, icmp_timestamp_analyzer_monitor_packet>>
    get_icmp_ts_req_rep_list();

    void change_timestamp_icmp_captured_time(icmp_type type, int id_number, int sequence_number,
                                             std::chrono::duration<long, std::ratio<1, 1000000000>> time);

    void change_timestamp_icmp_orig_ts(int id_number, int sequence_number,
                                       std::chrono::duration<long, std::ratio<1, 1000000000>> time);

    void change_timestamp_icmp_received_ts(int id_number, int sequence_number,
                                           std::chrono::duration<long, std::ratio<1, 1000000000>> time);

    void change_timestamp_icmp_transmit_ts(int id_number, int sequence_number,
                                           std::chrono::duration<long, std::ratio<1, 1000000000>> time);

    ~icmp_timestamp_analyzer_adapter();

private:
    std::vector<icmp_timestamp_analyzer_monitor_packet> icmp_packet_list;
};


#endif //PLATFORM_ICMP_ANALYZER_H
