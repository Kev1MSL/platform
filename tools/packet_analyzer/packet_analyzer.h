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
#include "pcapplusplus/ArpLayer.h"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/PcapFileDevice.h"
#include <random>
#include <tuple>
#include "icmp_analyzer.h"
#include <tabulate/table.hpp>
#include "../propagate_update/propagate_update.h"

#include <jsoncpp/json/json.h>
#include <jsoncpp/json/value.h>
#include <fstream>


enum experiment_type
{
    ICMP_ECHO,
    ICMP_TIMESTAMP,
    SIMPLE_CAPTURE
};

class packet_analyzer
{
public:
    packet_analyzer(const std::string &device_name);

    void print_device_info();

    void start_capture();

    void start_capture_for_experiment();

    void stop_capture(experiment_type type);

    void parse_simple_capture();

    void parse_icmp_echo_packets();

    void parse_icmp_timestamp_packets();

    void get_hw_address(const std::string &ip_address, pcpp::MacAddress &hw_address);

    void start_icmp_echo_experiment(const std::string &target_ip, int nb_packets, int packet_size, int interval);

    void start_icmp_timestamp_experiment(const std::string &target_ip, int nb_packets, int interval);

    static bool on_packet_arrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie);

    static void export_to_csv(const std::string &file_name,
                              std::vector<std::pair<icmp_echo_analyzer_monitor_packet, icmp_echo_analyzer_monitor_packet>> &icmp_packets);

    static void export_to_csv(const std::string &file_name,
                              std::vector<std::pair<icmp_timestamp_analyzer_monitor_packet, icmp_timestamp_analyzer_monitor_packet>> &timestamp_packets);

    bool get_monitor_ssh_config();

    ~packet_analyzer();

private:
    bool is_monitor_mode;
    ssh_config ssh_configuration;
    pcpp::PcapLiveDevice *m_device;
    pcpp::RawPacketVector packet_vector;

    std::vector<pcpp::RawPacket> packet_vector_4_monitor;


    std::vector<std::tuple<std::chrono::duration<long, std::ratio<1, 1000000000>>, std::chrono::duration<long, std::ratio<1, 1000000000>>>> icmp_packet_timestamps;

};

#endif // PLATFORM_PACKET_ANALYZER_H
