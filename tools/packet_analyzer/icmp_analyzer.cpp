//
// Created by Kevin Messali on 20/02/23.
//

#include "icmp_analyzer.h"

icmp_analyzer_monitor_packet::icmp_analyzer_monitor_packet()
{
    this->raw_data = nullptr;
    this->raw_data_len = 0;
    this->icmpType = NOT_ICMP;
    this->signal_strength = 0;
    this->sequence_number = 0;
    this->id_number = 0;
    this->wlan_duration = 0;

}

icmp_analyzer_monitor_packet::icmp_analyzer_monitor_packet(const uint8_t *raw_data, int raw_data_len,
                                                           timespec timestamp)
{

    this->raw_data = raw_data;
    this->raw_data_len = raw_data_len;

    bool is_icmp_req =
            icmp_analyzer_monitor_packet::get_byte_from_packet(84) == 0x8 &&
            icmp_analyzer_monitor_packet::get_byte_from_packet(85) == 0x0 &&
            icmp_analyzer_monitor_packet::get_byte_from_packet(73) == 0x1;
    bool is_icmp_rep =
            icmp_analyzer_monitor_packet::get_byte_from_packet(84) == 0x0 &&
            icmp_analyzer_monitor_packet::get_byte_from_packet(85) == 0x0 &&
            icmp_analyzer_monitor_packet::get_byte_from_packet(73) == 0x1;
    if (is_icmp_req)
        this->icmpType = ICMP_REQUEST;
    else if (is_icmp_rep)
        this->icmpType = ICMP_REPLY;
    else
        this->icmpType = NOT_ICMP;


    this->signal_strength = (int8_t) icmp_analyzer_monitor_packet::get_byte_from_packet(22);
    std::vector<uint8_t> raw_seq_number = icmp_analyzer_monitor_packet::get_bytes_from_packet(90, 92);
    this->sequence_number = ((uint16_t) raw_seq_number[0] << 8) | raw_seq_number[1];
    std::vector<uint8_t> raw_id_number = icmp_analyzer_monitor_packet::get_bytes_from_packet(88, 90);
    this->id_number = ((uint16_t) raw_id_number[0] << 8) | raw_id_number[1];
    std::vector<uint8_t> raw_timestamp = icmp_analyzer_monitor_packet::get_bytes_from_packet(92, 100);
    uint32_t tv_sec = (uint32_t) raw_timestamp[0] << 24 | (uint32_t) raw_timestamp[1] << 16 |
                      (uint32_t) raw_timestamp[2] << 8 | raw_timestamp[3];
    uint32_t tv_nsec = (uint32_t) raw_timestamp[4] << 24 | (uint32_t) raw_timestamp[5] << 16 |
                       (uint32_t) raw_timestamp[6] << 8 | raw_timestamp[7];
    auto icmp_duration_sent = std::chrono::seconds{tv_sec} +
                              std::chrono::nanoseconds{tv_nsec};

    this->sent_time = icmp_duration_sent;
    auto captured_duration = std::chrono::seconds{timestamp.tv_sec} +
                             std::chrono::nanoseconds{timestamp.tv_nsec};

    this->captured_time = captured_duration;

    auto raw_wlan_duration = icmp_analyzer_monitor_packet::get_bytes_from_packet
            (32, 34);
    this->wlan_duration = (uint32_t) raw_wlan_duration[1] << 8 | raw_wlan_duration[0];
}

icmp_analyzer_adapter::icmp_analyzer_adapter(const icmp_analyzer_monitor_packet &icmp_packet)
{
    this->icmp_packet_list.push_back(icmp_packet);
}

icmp_analyzer_adapter::~icmp_analyzer_adapter()
{
    this->icmp_packet_list.clear();
}

void icmp_analyzer_adapter::add_icmp_packet(const icmp_analyzer_monitor_packet &icmp_packet)
{
    for (size_t i = 0; i < this->icmp_packet_list.size(); i++)
    {
        if (this->icmp_packet_list[i].get_id_number() == icmp_packet.get_id_number() &&
            this->icmp_packet_list[i].get_sequence_number() == icmp_packet.get_sequence_number() &&
            this->icmp_packet_list[i].get_icmp_type() == icmp_packet.get_icmp_type())
        {
            this->icmp_packet_list[i] = icmp_packet;
            return;
        }
    }
    this->icmp_packet_list.push_back(icmp_packet);
}

icmp_analyzer_adapter::icmp_analyzer_adapter()
{
    this->icmp_packet_list.clear();
}

size_t icmp_analyzer_adapter::get_packet_count()
{
    return this->icmp_packet_list.size();
}

std::pair<icmp_analyzer_monitor_packet, icmp_analyzer_monitor_packet>
icmp_analyzer_adapter::get_icmp_req_rep(int sequence_number)
{
    icmp_analyzer_monitor_packet icmp_req;
    icmp_analyzer_monitor_packet icmp_rep;
    for (auto &packet: this->icmp_packet_list)
    {
        if (packet.get_sequence_number() == sequence_number)
        {
            if (packet.get_icmp_type() == ICMP_REQUEST)
                icmp_req = packet;
            else if (packet.get_icmp_type() == ICMP_REPLY)
                icmp_rep = packet;
        }
    }
    return std::make_pair(icmp_req, icmp_rep);
}

std::vector<std::pair<icmp_analyzer_monitor_packet, icmp_analyzer_monitor_packet>>
icmp_analyzer_adapter::get_icmp_req_rep_list()
{
    std::vector<std::pair<icmp_analyzer_monitor_packet, icmp_analyzer_monitor_packet>> icmp_req_rep_list;
    for (auto &packet: this->icmp_packet_list)
    {
        if (packet.get_icmp_type() == ICMP_REQUEST)
        {
            std::pair<icmp_analyzer_monitor_packet, icmp_analyzer_monitor_packet> icmp_req_rep = get_icmp_req_rep(
                    packet.get_sequence_number());
            icmp_req_rep_list.push_back(icmp_req_rep);
        }
    }
    return icmp_req_rep_list;
}

void icmp_analyzer_adapter::change_echo_icmp_req_rep_time(int id_number, int sequence_number,
                                                          std::chrono::duration<long, std::ratio<1, 1000000000>> time)
{
    for (auto &packet: this->icmp_packet_list)
    {
        if (packet.get_id_number() == id_number && packet.get_sequence_number() == sequence_number)
        {
            packet.set_sent_time(time);
        }
    }

}

void icmp_analyzer_adapter::change_echo_icmp_captured_time(icmp_type type, int id_number, int sequence_number,
                                                           std::chrono::duration<long, std::ratio<1, 1000000000>> time)
{
    for (auto &packet: this->icmp_packet_list)
    {
        if (packet.get_id_number() == id_number && packet.get_sequence_number() == sequence_number &&
            packet.get_icmp_type() == type)
        {
            packet.set_captured_time(time);
        }
    }

}

uint8_t icmp_analyzer_monitor_packet::get_byte_from_packet(int offset)
{
    if (offset >= this->raw_data_len)
        return 0;
    return this->raw_data[offset];
}

std::vector<uint8_t>
icmp_analyzer_monitor_packet::get_bytes_from_packet(int begin_offset, int end_offset)
{
    std::vector<uint8_t> bytes;
    for (int i = begin_offset; i < end_offset; ++i)
    {
        uint8_t byte = get_byte_from_packet(i);
        bytes.push_back(byte);
    }
    return bytes;
}

std::string icmp_analyzer_monitor_packet::print_time_captured()
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

std::string icmp_analyzer_monitor_packet::print_time_icmp_sent()
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

bool icmp_analyzer_monitor_packet::is_icmp_packet()
{
    return this->icmpType != NOT_ICMP;
}

icmp_type icmp_analyzer_monitor_packet::get_icmp_type() const
{
    return this->icmpType;
}

int icmp_analyzer_monitor_packet::get_signal_strength() const
{
    return this->signal_strength;
}

int icmp_analyzer_monitor_packet::get_sequence_number() const
{
    return this->sequence_number;
}

int icmp_analyzer_monitor_packet::get_id_number() const
{
    return this->id_number;
}

uint32_t icmp_analyzer_monitor_packet::get_wlan_duration() const
{
    return this->wlan_duration;
}

std::chrono::duration<long, std::ratio<1, 1000000000>> icmp_analyzer_monitor_packet::get_sent_time() const
{
    return this->sent_time;
}

std::chrono::duration<long, std::ratio<1, 1000000000>> icmp_analyzer_monitor_packet::get_captured_time() const
{
    return this->captured_time;
}

void icmp_analyzer_monitor_packet::set_sent_time(std::chrono::duration<long, std::ratio<1, 1000000000>> time)
{
    this->sent_time = time;
}

void icmp_analyzer_monitor_packet::set_captured_time(std::chrono::duration<long, std::ratio<1, 1000000000>> time)
{
    this->captured_time = time;
}

int icmp_analyzer_monitor_packet::get_data_len() const
{
    // Remove 54 bytes added from the RadioTap headers
    return this->raw_data_len - 54;
}
