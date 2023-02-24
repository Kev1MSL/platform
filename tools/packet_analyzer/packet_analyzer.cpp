//
// Created by Kevin Messali on 16/02/23.
//


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
    /*std::ifstream monitor_config_file("static/monitor.json");
    Json::Value json_monitor_config;*/
/*    if (!monitor_config_file.good())
    {
        std::cout << "ERROR: Unable to open devices.json. Launching is non-monitor mode." << std::endl;
        this->m_device->startCapture(this->packet_vector_4_monitor);
        return;
    }*/

    /*monitor_config_file >> json_monitor_config;

    this->is_monitor_mode = json_monitor_config["MONITOR_ENABLED"].asBool();*/
    bool only_icmp = this->get_monitor_ssh_config();

    if (this->is_monitor_mode)
    {
        ssh_updater ssh_updater(this->ssh_configuration);
        this->m_device->startCapture(this->packet_vector);
        ssh_updater.start_monitor(only_icmp);
    } /*else
    {
        // start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
        this->m_device->startCapture(this->packet_vector_4_monitor);
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
        this->m_device->stopCapture();
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
            this->packet_vector_4_monitor.push_back(rawPacket);
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
    for (const pcpp::RawPacket &packet: this->packet_vector_4_monitor)
    {
        /*pcpp::Packet parsedPacket(packet);*/
        icmp_analyzer_monitor_packet icmp_packet
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

    for (auto &iter: this->packet_vector)
    {
        pcpp::Packet parsedPacket(iter);
        if (!parsedPacket.getLayerOfType(pcpp::ICMP))
        {
            continue;
        }
        auto *icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
        if (icmpLayer->getIcmpHeader()->type == 0x8)
        {
            icmp_analyzer_monitor_packet icmp_packet
                    (iter->getRawData(),
                     iter->getRawDataLen(),
                     iter->getPacketTimeStamp());
            std::vector<uint8_t> raw_timestamp = icmp_packet.get_bytes_from_packet(42, 50);
            uint32_t tv_sec = (uint32_t) raw_timestamp[0] << 24 | (uint32_t) raw_timestamp[1] << 16 |
                              (uint32_t) raw_timestamp[2] << 8 | raw_timestamp[3];
            uint32_t tv_nsec = (uint32_t) raw_timestamp[4] << 24 | (uint32_t) raw_timestamp[5] << 16 |
                               (uint32_t) raw_timestamp[6] << 8 | raw_timestamp[7];
            auto icmp_duration_sent = std::chrono::seconds{tv_sec} +
                                      std::chrono::nanoseconds{tv_nsec};
            auto id = __bswap_constant_16(icmpLayer->getEchoRequestData()->header->id);
            auto sequence = __bswap_constant_16(icmpLayer->getEchoRequestData()->header->sequence);
            adapter.change_echo_icmp_req_rep_time(id,
                                                  sequence,
                                                  icmp_duration_sent);

            auto duration = std::chrono::seconds{parsedPacket.getRawPacket()->getPacketTimeStamp().tv_sec} +
                            std::chrono::nanoseconds{parsedPacket.getRawPacket()->getPacketTimeStamp().tv_nsec};

            auto time = std::chrono::time_point<std::chrono::system_clock, std::chrono::nanoseconds>{duration};
            adapter.change_echo_icmp_captured_time(ICMP_REQUEST, id, sequence, duration);

        } else if (icmpLayer->getIcmpHeader()->type == 0x0)
        {
            auto duration = std::chrono::seconds{parsedPacket.getRawPacket()->getPacketTimeStamp().tv_sec} +
                            std::chrono::nanoseconds{parsedPacket.getRawPacket()->getPacketTimeStamp().tv_nsec};
            auto id = __bswap_constant_16(icmpLayer->getEchoReplyData()->header->id);
            auto sequence = __bswap_constant_16(icmpLayer->getEchoReplyData()->header->sequence);
            adapter.change_echo_icmp_captured_time(ICMP_REPLY, id, sequence, duration);
        }

    }
    std::cout << std::endl << "Differences between ICMP packets: " << std::endl;
    std::vector<std::pair<icmp_analyzer_monitor_packet, icmp_analyzer_monitor_packet>> icmp_packets = adapter.get_icmp_req_rep_list();
    for (std::pair<icmp_analyzer_monitor_packet, icmp_analyzer_monitor_packet> packet: icmp_packets)
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
    export_to_csv("results/icmp_echo_experiment.csv", icmp_packets);

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

bool packet_analyzer::on_packet_arrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie)
{
    pcpp::Packet parsedPacket(packet);
    if (parsedPacket.isPacketOfType(pcpp::ARP))
    {
        auto *arpLayer = parsedPacket.getLayerOfType<pcpp::ArpLayer>();
        auto header = arpLayer->getArpHeader();
        if (__bswap_constant_16(arpLayer->getArpHeader()->opcode) == pcpp::ARP_REPLY)
        {
            auto *mac = (pcpp::MacAddress *) cookie;
            *mac = arpLayer->getArpHeader()->senderMacAddr;
            std::cout << "Got ARP reply" << std::endl;
            dev->stopCapture();
            return false;
        }
    }
    return true;
}

void
packet_analyzer::start_icmp_echo_experiment(const std::string &target_ip, int nb_packets, int packet_size, int interval)
{
    // Send an ARP request to get the MAC address of the target
    pcpp::EthLayer ethLayer(this->m_device->getMacAddress(), pcpp::MacAddress("ff:ff:ff:ff:ff:ff"), PCPP_ETHERTYPE_ARP);
    pcpp::ArpLayer arpLayer(pcpp::ARP_REQUEST, this->m_device->getMacAddress(), pcpp::MacAddress("ff:ff:ff:ff:ff:ff"),
                            this->m_device->getIPv4Address(),
                            pcpp::IPv4Address(target_ip));
    pcpp::Packet arpPacket(42);
    arpPacket.addLayer(&ethLayer);
    arpPacket.addLayer(&arpLayer);
    arpPacket.computeCalculateFields();
    this->m_device->sendPacket(&arpPacket);
    pcpp::MacAddress hw_address_to_ping;
    this->m_device->startCaptureBlockingMode(on_packet_arrives, &hw_address_to_ping, 1000);
    std::cout << "MAC address to ping: " << hw_address_to_ping << std::endl;
    // Start capture
    this->start_capture();
    pcpp::multiPlatformSleep(1);
    std::random_device rd;
    // Random sequence sequence id
    auto seq_id = rd();
    for (int i = 0; i < nb_packets; ++i)
    {
        // Send ICMP packets
        pcpp::EthLayer ethLayer4icmp(this->m_device->getMacAddress(), hw_address_to_ping, PCPP_ETHERTYPE_IP);
        pcpp::IPv4Layer ipLayer4icmp(pcpp::IPv4Address(this->m_device->getIPv4Address()),
                                     pcpp::IPv4Address(target_ip));


        auto ip_id = rd();
        ipLayer4icmp.getIPv4Header()->timeToLive = 64;
        ipLayer4icmp.getIPv4Header()->ipId = htons(ip_id);


        auto *data = new uint8_t[packet_size];
        std::generate_n(data, packet_size, std::ref(rd));
        auto time = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::high_resolution_clock::now().time_since_epoch()).count();

        std::cout << time << std::endl;
        pcpp::IcmpLayer icmpLayer;

        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::high_resolution_clock::now().time_since_epoch());
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
        auto nanoseconds_only = duration - std::chrono::seconds(seconds);
        std::cout << "Seconds: " << seconds << std::endl;
        std::cout << "Nanoseconds: " << nanoseconds_only.count() << std::endl;
        auto timestamp = seconds << 32 | nanoseconds_only.count();

        //icmpLayer.getEchoRequestData()->header->timestamp = __bswap_constant_64(timestamp);
        std::cout << "Timestamp: " << duration.count() << std::endl;
        icmpLayer.setEchoRequestData(seq_id, i, __bswap_constant_64(timestamp), data, packet_size + 6);
        std::stringstream ss;
        ss << std::hex << timestamp << std::endl;
        std::cout << "Timestamp: " << ss.str() << std::endl;
        pcpp::Packet icmpPacket(50 + packet_size);
        icmpPacket.addLayer(&ethLayer4icmp);
        icmpPacket.addLayer(&ipLayer4icmp);
        icmpPacket.addLayer(&icmpLayer);
        icmpPacket.computeCalculateFields();

        this->m_device->sendPacket(&icmpPacket);
        std::this_thread::sleep_for(std::chrono::milliseconds(interval));

    }
    // Stop capture
    pcpp::multiPlatformSleep(1);
    this->stop_capture();

}

bool packet_analyzer::get_monitor_ssh_config()
{
    std::ifstream monitor_config_file("static/monitor.json");
    Json::Value json_monitor_config;
    monitor_config_file >> json_monitor_config;
    this->is_monitor_mode = json_monitor_config["MONITOR_ENABLED"].asBool();
    this->ssh_configuration.host = json_monitor_config["MONITOR_IP"].asString();
    this->ssh_configuration.username = json_monitor_config["MONITOR_USERNAME"].asString();
    this->ssh_configuration.password = json_monitor_config["MONITOR_PASSWORD"].asString();
    return json_monitor_config["ONLY_ICMP"].asBool();
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

void packet_analyzer::export_to_csv(const std::string &file_name,
                                    std::vector<std::pair<icmp_analyzer_monitor_packet, icmp_analyzer_monitor_packet>> &icmp_packets)
{
    std::ofstream csv_file(file_name);
    csv_file
            << "ICMP_type,Identifier,Sequence,Sent_timestamp,Captured_timestamp,Packet_size,Signal_strength,WLAN_duration"
            << std::endl;
    for (auto &icmp_packet: icmp_packets)
    {
        auto icmp_request = icmp_packet.first;
        auto icmp_reply = icmp_packet.second;
        csv_file << icmp_request.get_icmp_type() << "," << icmp_request.get_id_number() << ","
                 << icmp_request.get_sequence_number()
                 << "," << icmp_request.get_sent_time().count() << "," << icmp_request.get_captured_time().count()
                 << ","
                 << icmp_request.get_data_len() << "," << icmp_request.get_signal_strength() << ","
                 << icmp_request.get_wlan_duration() << std::endl;
        csv_file << icmp_reply.get_icmp_type() << "," << icmp_reply.get_id_number() << ","
                 << icmp_reply.get_sequence_number()
                 << "," << icmp_reply.get_sent_time().count() << "," << icmp_reply.get_captured_time().count() << ","
                 << icmp_reply.get_data_len() << "," << icmp_reply.get_signal_strength() << ","
                 << icmp_reply.get_wlan_duration() << std::endl;
    }
    csv_file.close();

}

