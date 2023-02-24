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

#define IS_MONITOR_MODE 1

class packet_analyzer
{
public:
    packet_analyzer(const std::string &device_name);

    void print_device_info();

    void start_capture();

    void stop_capture();

    void parse_packets();

    void start_icmp_echo_experiment(const std::string &target_ip, int nb_packets, int packet_size, int interval);

    static bool on_packet_arrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie);

    static void export_to_csv(const std::string &file_name,
                              std::vector<std::pair<icmp_analyzer_monitor_packet, icmp_analyzer_monitor_packet>> &icmp_packets);

    bool get_monitor_ssh_config();

    ~packet_analyzer();

private:
    bool is_monitor_mode;
    ssh_config ssh_configuration;
    pcpp::PcapLiveDevice *m_device;
    pcpp::RawPacketVector packet_vector;

    std::vector<pcpp::RawPacket> packet_vector_4_monitor;


    std::vector<std::tuple<std::chrono::duration<long, std::ratio<1, 1000000000>>, std::chrono::duration<long, std::ratio<1, 1000000000>>>> icmp_packet_timestamps;

    static std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType);

};

#endif // PLATFORM_PACKET_ANALYZER_H
