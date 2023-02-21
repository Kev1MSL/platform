//
// Created by Kevin Messali on 20/02/23.
//

#include "icmp_analyzer.h"


icmp_analyzer_packet::icmp_analyzer_packet(const uint8_t *raw_data, int raw_data_len, timespec captured_tv_sec,
                                           timespec captured_tv_nsec)
{
    bool is_icmp_req =
            icmp_analyzer_packet::get_byte_from_packet(83) == 0x8 &&
            icmp_analyzer_packet::get_byte_from_packet(84) == 0x0 &&
            icmp_analyzer_packet::get_byte_from_packet(29) == 0x88;
    bool is_icmp_rep =
            icmp_analyzer_packet::get_byte_from_packet(83) == 0x0 &&
            icmp_analyzer_packet::get_byte_from_packet(84) == 0x0 &&
            icmp_analyzer_packet::get_byte_from_packet(29) == 0x88;
    if (is_icmp_req)
        this->icmpType = ICMP_REQUEST;
    else if (is_icmp_rep)
        this->icmpType = ICMP_REPLY;
    else
        this->icmpType = NOT_ICMP;

    this->raw_data = raw_data;
    this->raw_data_len = raw_data_len;

    this->signal_strength = (int8_t) icmp_analyzer_packet::get_byte_from_packet(22);
    std::vector<uint8_t> raw_seq_number = icmp_analyzer_packet::get_bytes_from_packet(89, 91);
    this->sequence_number = ((uint16_t) raw_seq_number[0] << 8) | raw_seq_number[1];
    std::vector<uint8_t> raw_id_number = icmp_analyzer_packet::get_bytes_from_packet(87, 89);
    this->id_number = ((uint16_t) raw_id_number[0] << 8) | raw_id_number[1];
    std::vector<uint8_t> raw_timestamp = icmp_analyzer_packet::get_bytes_from_packet(91, 99);
    uint32_t tv_sec = (uint32_t) raw_timestamp[0] << 24 | (uint32_t) raw_timestamp[1] << 16 |
                      (uint32_t) raw_timestamp[2] << 8 | raw_timestamp[3];
    uint32_t tv_nsec = (uint32_t) raw_timestamp[4] << 24 | (uint32_t) raw_timestamp[5] << 16 |
                       (uint32_t) raw_timestamp[6] << 8 | raw_timestamp[7];
    auto icmp_duration_sent = std::chrono::seconds{tv_sec} +
                              std::chrono::nanoseconds{tv_nsec};

    this->sent_time = icmp_duration_sent;
    auto captured_duration = std::chrono::seconds{captured_tv_sec.tv_sec} +
                             std::chrono::nanoseconds{captured_tv_nsec.tv_nsec};

    this->captured_time = captured_duration;

    auto raw_wlan_duration = icmp_analyzer_packet::get_bytes_from_packet
            (31, 33);
    this->wlan_duration = (uint32_t) raw_wlan_duration[1] << 8 | raw_wlan_duration[0];
}

icmp_analyzer_adapter::icmp_analyzer_adapter(const icmp_analyzer_packet &icmp_packet)
{
    this->icmp_packet_list.push_back(icmp_packet);
}

icmp_analyzer_adapter::~icmp_analyzer_adapter()
{
    this->icmp_packet_list.clear();
}

void icmp_analyzer_adapter::add_icmp_packet(const icmp_analyzer_packet &icmp_packet)
{
    this->icmp_packet_list.push_back(icmp_packet);
}

icmp_analyzer_adapter::icmp_analyzer_adapter()
{
    this->icmp_packet_list.clear();
}

uint8_t icmp_analyzer_packet::get_byte_from_packet(int offset)
{
    if (offset >= this->raw_data_len)
        return 0;
    return this->raw_data[offset];
}

std::vector<uint8_t>
icmp_analyzer_packet::get_bytes_from_packet(int begin_offset, int end_offset)
{
    std::vector<uint8_t> bytes;
    for (int i = begin_offset; i < end_offset; ++i)
    {
        uint8_t byte = get_byte_from_packet(i);
        bytes.push_back(byte);
    }
    return bytes;
}

std::string icmp_analyzer_packet::print_time_captured()
{
    auto cap_time = std::chrono::time_point<std::chrono::system_clock, std::chrono::nanoseconds>{
            this->captured_time};
    auto captured_t = std::chrono::system_clock::to_time_t(cap_time);
    auto tm = std::localtime(&captured_t);
    auto fr =
            std::chrono::duration_cast<std::chrono::nanoseconds>(cap_time.time_since_epoch()).count() % 1000000000;
    std::stringstream ss;
    ss << std::put_time(tm, "%d/%m/%Y %T.") << fr;
    return ss.str();
}

std::string icmp_analyzer_packet::print_time_icmp_sent()
{
    auto icmp_time = std::chrono::time_point<std::chrono::system_clock, std::chrono::nanoseconds>{
            this->sent_time};
    auto icmp_t = std::chrono::system_clock::to_time_t(icmp_time);
    auto tm = std::localtime(&icmp_t);
    auto fr =
            std::chrono::duration_cast<std::chrono::nanoseconds>(icmp_time.time_since_epoch()).count() % 1000000000;
    std::stringstream ss;
    ss << std::put_time(tm, "%d/%m/%Y %T.") << fr;
    return ss.str();
}
