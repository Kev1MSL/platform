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

    // start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
    this->m_device->startCapture(this->packet_vector);
}

void packet_analyzer::stop_capture()
{
    std::cout << std::endl
              << "Stopping capture..." << std::endl;

    // stop the capture
    this->m_device->stopCapture();

    std::cout << std::endl
              << "Capture stopped" << std::endl;
    packet_analyzer::parse_packets();
}

void packet_analyzer::parse_packets()
{
    icmp_analyzer_adapter adapter;
    for (auto packet: this->packet_vector)
    {
        pcpp::Packet parsedPacket(packet);
        icmp_analyzer_packet icmp_packet
                (parsedPacket.getRawPacket()->getRawData(),
                 parsedPacket.getRawPacket()->getRawDataLen(),
                 parsedPacket.getRawPacket()->getPacketTimeStamp());

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
    for (int i = 0; i < icmp_packets.size(); ++i)
    {
        auto diff = std::chrono::duration_cast<std::chrono::nanoseconds>(
                icmp_packets[i].second.get_captured_time() - icmp_packets[i].first.get_captured_time()).count() /
                    1000;
        float diff_f = diff / 1000.0;
        std::cout << "Packet " << i << ": "
                  << std::setprecision(6) << diff_f << " ms"
                  << std::endl;
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
