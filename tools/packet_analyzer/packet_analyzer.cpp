//
// Created by Kevin Messali on 16/02/23.
//


#include <pcap/dlt.h>
#include <pcap/pcap.h>
#include "packet_analyzer.h"

packet_analyzer::packet_analyzer(const std::string &device_name)
{
    this->m_device = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(device_name);
    if (this->m_device == nullptr)
    {
        throw std::runtime_error("Device not found");
    }
    if (!this->m_device->open())
    {
        throw std::runtime_error("Cannot open device");
    }
}

packet_analyzer::~packet_analyzer()
{
    this->m_device->close();
}

void packet_analyzer::print_device_info()
{
    // before capturing packets let's print some info about this interface
    std::cout
            << "Interface info:" << std::endl
            << "   Interface name:        " << this->m_device->getName()
            << std::endl                   // get interface name
            << "   Interface description: " << this->m_device->getDesc()
            << std::endl                   // get interface description
            << "   IP address:            " << this->m_device->getIPv4Address().toString()
            << std::endl // get interface IP address
            << "   MAC address:           " << this->m_device->getMacAddress()
            << std::endl             // get interface MAC address
            << "   Default gateway:       " << this->m_device->getDefaultGateway()
            << std::endl         // get default gateway
            << "   Interface MTU:         " << this->m_device->getMtu()
            << std::endl;                   // get interface MTU

    // get DNS servers
    if (!this->m_device->getDnsServers().empty())
        std::cout << "   DNS server:            " << this->m_device->getDnsServers().at(0) << std::endl;
}

// /**
//  * A callback function for the async capture which is called each time a packet is captured
//  */
// void packet_analyzer::onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie)
// {
//     // extract the stats object form the cookie
//     PacketStats *stats = (PacketStats *)cookie;

//     // parsed the raw packet
//     pcpp::Packet parsedPacket(packet);

//     // collect stats from packet
//     stats->consumePacket(parsedPacket);
// }

void packet_analyzer::start_capture()
{
    std::cout << std::endl
              << "Starting async capture..." << std::endl;
    std::ifstream monitor_config_file("static/monitor.json");
    Json::Value json_monitor_config;
/*    if (!monitor_config_file.good())
    {
        std::cout << "ERROR: Unable to open devices.json. Launching is non-monitor mode." << std::endl;
        this->m_device->startCapture(this->packet_vector);
        return;
    }*/

    monitor_config_file >> json_monitor_config;

    this->is_monitor_mode = json_monitor_config["MONITOR_ENABLED"].asBool();

    if (this->is_monitor_mode)
    {
        this->ssh_configuration.host = json_monitor_config["MONITOR_IP"].asString();
        this->ssh_configuration.username = json_monitor_config["MONITOR_USERNAME"].asString();
        this->ssh_configuration.password = json_monitor_config["MONITOR_PASSWORD"].asString();
        ssh_updater ssh_updater(this->ssh_configuration);
        ssh_updater.start_monitor(json_monitor_config["ONLY_ICMP"].asBool());
    } /*else
    {
        // start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
        this->m_device->startCapture(this->packet_vector);
    }*/
}

void packet_analyzer::stop_capture()
{
    std::cout << std::endl
              << "Stopping capture..." << std::endl;

    // stop the capture
    if (this->is_monitor_mode)
    {
        ssh_updater ssh_updater(this->ssh_configuration);
        ssh_updater.stop_monitor();
        pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("cache/monitor.pcap");
        if (reader == nullptr || !reader->open())
        {
            std::cout << "ERROR: Unable to open monitor.pcap" << std::endl;
            return;
        }
        pcpp::RawPacket rawPacket;
        while (reader->getNextPacket(rawPacket))
        {
            this->packet_vector.push_back(rawPacket);
        }
        reader->close();
        delete reader;
    } else
    {
        this->m_device->stopCapture();
    }


    std::cout << std::endl
              << "Capture stopped" << std::endl;
    packet_analyzer::parse_packets();
}

void packet_analyzer::parse_packets()
{
    icmp_analyzer_adapter adapter;
    for (const pcpp::RawPacket &packet: this->packet_vector)
    {
        /*pcpp::Packet parsedPacket(packet);*/
        icmp_analyzer_packet icmp_packet
                (packet.getRawData(),
                 packet.getRawDataLen(),
                 packet.getPacketTimeStamp());

#if IS_MONITOR_MODE == 1
        if (!icmp_packet.is_icmp_packet())
            continue;
        std::cout << "----------------------------------" << std::endl;
        adapter.add_icmp_packet(icmp_packet);
        std::cout << "ICMP " << (icmp_packet.get_icmp_type() == ICMP_REQUEST ? "Request" : "Reply") << std::endl;
        std::cout << "Signal strength: " << icmp_packet.get_signal_strength() << std::endl;
        std::cout << "Sequence number: " << icmp_packet.get_sequence_number() << std::endl;
        std::stringstream ss;
        ss << std::hex << icmp_packet.get_id_number();
        std::cout << "ID number: 0x" << ss.str() << " | " << icmp_packet.get_id_number() << std::endl;
        std::cout << "ICMP time: " << icmp_packet.print_time_icmp_sent() << std::endl;
        std::cout << "Captured time: " << icmp_packet.print_time_captured() << std::endl;
        std::cout << "WLAN duration: " << icmp_packet.get_wlan_duration() << " µs" << std::endl;
        std::cout << "----------------------------------" << std::endl;
    }
    std::cout << std::endl << "Differences between ICMP packets: " << std::endl;
    std::vector<std::pair<icmp_analyzer_packet, icmp_analyzer_packet>> icmp_packets = adapter.get_icmp_req_rep_list();
    for (std::pair<icmp_analyzer_packet, icmp_analyzer_packet> packet: icmp_packets)
    {
        tabulate::Table table;
        table.add_row({"", "ICMP Request", "ICMP Reply"});
        table.add_row({"Sequence number", std::to_string(packet.first.get_sequence_number()),
                       std::to_string(packet.second.get_sequence_number())});
        std::stringstream ss;
        ss << std::hex << packet.first.get_id_number();
        table.add_row({"ID number", "0x" + ss.str() + " | " + std::to_string(packet.first.get_id_number()),
                       "0x" + ss.str() + " | " + std::to_string(packet.second.get_id_number())});
        table.add_row({"Signal strength", std::to_string(packet.first.get_signal_strength()) + " dBm",
                       std::to_string(packet.second.get_signal_strength()) + " dBm"});
        table.add_row({"ICMP time", packet.first.print_time_icmp_sent(), packet.second.print_time_icmp_sent()});
        table.add_row({"Captured time", packet.first.print_time_captured(), packet.second.print_time_captured()});
        table.add_row({"WLAN duration", std::to_string(packet.first.get_wlan_duration()) + " µs",
                       std::to_string(packet.second.get_wlan_duration()) + " µs"});

        auto diff = std::chrono::duration_cast<std::chrono::nanoseconds>(
                packet.second.get_captured_time() - packet.first.get_captured_time()).count() /
                    1000;
        float diff_f = diff / 1000.0;

        tabulate::Table difference;
        std::stringstream ss_diff;
        ss_diff << std::dec << std::setprecision(6) << diff_f;
        table.add_row({"Difference", ss_diff.str() + " ms", ss_diff.str() + " ms"});
        table.format().font_align(tabulate::FontAlign::center);
        table.row(6).format().multi_byte_characters(true);
        std::cout << table << std::endl << std::endl << std::endl;

    }
#else
    std::cout << "----------------------------------" << std::endl;
    std::cout << "Packet incoming" << std::endl;
    if (!parsedPacket.getLayerOfType(pcpp::ICMP))
    {
        continue;
    }
    std::vector<std::string> packet_data;
    parsedPacket.toStringList(packet_data);
    for (const auto &line: packet_data)
    {
        std::cout << line << std::endl;
    }
    auto duration = std::chrono::seconds{parsedPacket.getRawPacket()->getPacketTimeStamp().tv_sec} +
                    std::chrono::nanoseconds{parsedPacket.getRawPacket()->getPacketTimeStamp().tv_nsec};
    std::cout << "Duration: " << duration.count() << std::endl;
    auto time = std::chrono::time_point<std::chrono::system_clock, std::chrono::nanoseconds>{duration};
    auto t = std::chrono::system_clock::to_time_t(time);
    std::cout << "Packet timestamp: " << packet_analyzer::print_time(t, time) << std::endl;

    auto *icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
    if (icmpLayer == nullptr)
    {
        std::cout << "No ICMP layer" << std::endl;
        continue;
    }
    pcpp::icmp_echo_request *req = icmpLayer->getEchoRequestData();
    pcpp::icmp_echo_reply *rep = icmpLayer->getEchoReplyData();
    if (req != nullptr)
    {
        int seq_number = __bswap_constant_16(req->header->sequence);
        std::cout << "ICMP sequence number: " << __bswap_constant_16(req->header->sequence) << std::endl;
        this->icmp_packet_timestamps.push_back(std::tuple(duration, std::chrono::nanoseconds{0}));

    }
    if (rep != nullptr)
    {
        int seq_number = __bswap_constant_16(rep->header->sequence);
        std::cout << "ICMP sequence number: " << __bswap_constant_16(rep->header->sequence) << std::endl;
        if (seq_number - 1 < this->icmp_packet_timestamps.size())
            this->icmp_packet_timestamps[seq_number - 1] = std::tuple(
                    std::get<0>(this->icmp_packet_timestamps[seq_number - 1]), duration);

    }
    std::cout << "----------------------------------" << std::endl;
}
std::cout << std::endl << "Differences between ICMP packets: " << std::endl;
for (int i = 0; i < this->icmp_packet_timestamps.size(); ++i)
{
    auto diff = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::get<1>(this->icmp_packet_timestamps[i]) - std::get<0>(this->icmp_packet_timestamps[i])).count() /
                1000;
    float diff_f = diff / 1000.0;
    std::cout << "Packet " << i + 1 << ": "
              << std::setprecision(6) << diff_f << " ms"
              << std::endl;
}
#endif


}

std::string packet_analyzer::getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
    switch (protocolType)
    {
        case pcpp::Ethernet:
            return "Ethernet";
        case pcpp::IPv4:
            return "IPv4";
        case pcpp::IPv6:
            return "IPv6";
        case pcpp::TCP:
            return "TCP";
        case pcpp::UDP:
            return "UDP";
        case pcpp::SSL:
            return "SSL";
        case pcpp::DNS:
            return "DNS";
        case pcpp::HTTP:
            return "HTTP";
        case pcpp::PPP_PPTP:
            return "PPP_PPTP";
        case pcpp::GRE:
            return "GRE";
        case pcpp::VLAN:
            return "VLAN";
        case pcpp::MPLS:
            return "MPLS";
        case pcpp::PPPoE:
            return "PPPoE";
        case pcpp::SLL:
            return "SLL";
        case pcpp::ARP:
            return "ARP";
        case pcpp::ICMP:
            return "ICMP";
        default:
            return "Unknown";
    }
}
