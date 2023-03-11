//
// Created by kevin on 16/02/23.
//

#ifndef TOOLS_PACKET_ANALYZER_PACKET_ANALYZER
#define TOOLS_PACKET_ANALYZER_PACKET_ANALYZER

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

/// @brief Experiment type enum - used to determine which experiment to run.
enum experiment_type
{
    /// @brief ICMP echo experiment.
    ICMP_ECHO,
    /// @brief ICMP timestamp experiment.
    ICMP_TIMESTAMP,
    /// @brief Simple capture experiment.
    SIMPLE_CAPTURE
};

/// @brief Packet analyzer class, used to analyze packets on a given interface and perform experiments.
class packet_analyzer
{
public:
    /// @brief Constructor for packet analyzer.
    /// @param device_name The name of the interface to use for analyze.
    packet_analyzer(const std::string &device_name);

    /// @brief Print the device info.
    void print_device_info();

    /// @brief Start a simple async capture on the device.
    void start_capture();

    /// @brief Start a capture for an experiment. This function might call the monitor RPI to start a monitoring capture.
    void start_capture_for_experiment();

    /// @brief Stop the async capture.
    /// @param type The type of experiment that was running. If monitoring mode was enabled, it will download the capture from the monitoring device.
    void stop_capture(experiment_type type);

    /// @brief Parse the simple capture and output the results in the terminal.
    void parse_simple_capture();

    /// @brief Parse the ICMP echo packets from the ICMP echo experiment and output the results in the terminal. It will also export the results to a CSV file at results/icmp_echo_experiment.csv.
    void parse_icmp_echo_packets();

    /// @brief Parse the ICMP timestamp packets from the ICMP timestamp experiment and output the results in the terminal. It will also export the results to a CSV file at results/icmp_timestamp_experiment.csv.
    void parse_icmp_timestamp_packets();

    /// @brief Get the hardware address of a given IP address. It will use ARP to get the hardware address.
    /// @param ip_address The IP address to get the hardware address for.
    /// @param hw_address A reference to a MacAddress object to store the hardware address in.
    void get_hw_address(const std::string &ip_address, pcpp::MacAddress &hw_address);

    /// @brief Start the ICMP echo experiment, on a given target IP address with a given number of packets, packet size and interval.
    /// @param target_ip The target IP address to send the ICMP echo packets to.
    /// @param nb_packets The number of packets to send.
    /// @param packet_size The size of each packet.
    /// @param interval The interval between each packet.
    void start_icmp_echo_experiment(const std::string &target_ip, int nb_packets, int packet_size, int interval);

    /// @brief Start the ICMP timestamp experiment, on a given target IP address with a given number of packets and interval.
    /// @param target_ip The target IP address to send the ICMP timestamp packets to.
    /// @param nb_packets The number of packets to send.
    /// @param interval The interval between each packet.
    void start_icmp_timestamp_experiment(const std::string &target_ip, int nb_packets, int interval);

    /// @brief Blocking function that listens for packets on the device and stores them into a cookie. This function is used for getting the hardware address of a given IP address when the ARP packet arrives.
    /// @param packet The packet that arrived.
    /// @param dev The device that the packet arrived on.
    /// @param cookie A cookie that can be used to store data.
    /// @return True if the experiment should continue, false otherwise.
    static bool on_packet_arrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie);

    /// @brief Export to CSV file the results from the ICMP echo experiment.
    /// @param file_name The name of the file to export to. By default results/icmp_echo_experiment.csv.
    /// @param icmp_packets A vector of ICMP echo packets.
    static void export_to_csv(
            std::vector<std::pair<icmp_echo_analyzer_monitor_packet, icmp_echo_analyzer_monitor_packet>> &icmp_packets,
            const std::string &file_name = "results/icmp_echo_experiment.csv");

    /// @brief Export to CSV file the results from the ICMP timestamp experiment.
    /// @param file_name The name of the file to export to. By default results/icmp_timestamps_experiment.csv.
    /// @param timestamp_packets A vector of ICMP timestamp packets.
    static void export_to_csv(
            std::vector<std::pair<icmp_timestamp_analyzer_monitor_packet, icmp_timestamp_analyzer_monitor_packet>> &timestamp_packets,
            const std::string &file_name = "results/icmp_timestamps_experiment.csv");

    /// @brief Get the monitoring ssh configuration from the config file at static/monitor.json
    /// @return True if filtering only icmp packets, false otherwise.
    bool get_monitor_ssh_config();

    /// @brief Send a packet from the defined interface.
    /// @param packet The packet to send.
    void send_packet(pcpp::Packet *packet);

    /// @brief Get the defined interface hardware address.
    /// @return The hardware address of the defined interface.
    pcpp::MacAddress get_current_device_hw_address();

    ~packet_analyzer();

private:
    bool is_monitor_mode;
    ssh_config ssh_configuration;
    pcpp::PcapLiveDevice *m_device;
    pcpp::RawPacketVector packet_vector;

    std::vector<pcpp::RawPacket> packet_vector_4_monitor;

    std::vector<std::tuple<std::chrono::duration<long, std::ratio<1, 1000000000>>, std::chrono::duration<long, std::ratio<1, 1000000000>>>> icmp_packet_timestamps;
};

#endif /* TOOLS_PACKET_ANALYZER_PACKET_ANALYZER */
