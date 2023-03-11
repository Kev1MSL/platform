//
// Created by Kevin Messali on 11/03/23.
//

#ifndef PLATFORM_RFI_GENERATOR_H
#define PLATFORM_RFI_GENERATOR_H

#include <string>
#include "../packet_analyzer/packet_analyzer.h"

/// @brief RFI generator class, used to generate RFI on a given interface.
class rfi_generator
{
public:
    /// @brief Constructor for RFI generator.
    /// @param iface The interface to generate RFI on.
    /// @param ip_address The IP address of the target.
    rfi_generator(const std::string &iface, const std::string &ip_address);

    /// @brief Destructor for RFI generator.
    ~rfi_generator();

    /// @brief Start a ping flood on the target for a given duration.
    /// @param duration The duration in ms of the ping flood.
    /// @param packet_size The size of each packet.
    /// @param interval The interval between each packet.
    void start_ping_flood_duration(int packet_size, int duration, int interval);

    /// @brief Start a ping flood on the target.
    /// @param packet_size The size of each packet.
    /// @param interval The interval between each packet.
    [[noreturn]] void start_ping_flood(int packet_size, int interval);

    /// @brief Send a ping or several ping requests to the target.
    /// @param num_packets Number of packets to send.
    /// @param packet_size The size of each packet.
    /// @param interval The interval between each packet in ms.
    void send_ping(int num_packets, int packet_size, int interval = 0);

    /// @brief [Feature not implemented yet] Send a flood of malformed association requests to the target, to cause a denial of service. This function requires to have the interface in monitor mode.
    /// @param fake_source_ip The fake source IP address to use in the malformed association requests.
    /// @param packet_size The size of each packet.
    /// @param interval The interval between each packet in ms.
    void send_malformed_association_request_flood(const std::string &fake_source_ip, int packet_size, int interval);

private:
    std::string target_address;
    std::string interface;
    std::string target_hw_address;
    // pcpp::PcapLiveDevice *m_device;
    packet_analyzer *analyzer;
};


#endif //PLATFORM_RFI_GENERATOR_H
