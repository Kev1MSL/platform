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
            << std::endl // get interface name
            << "   Interface description: " << this->m_device->getDesc()
            << std::endl // get interface description
            << "   IP address:            " << this->m_device->getIPv4Address().toString()
            << std::endl // get interface IP address
            << "   MAC address:           " << this->m_device->getMacAddress()
            << std::endl // get interface MAC address
            << "   Default gateway:       " << this->m_device->getDefaultGateway()
            << std::endl // get default gateway
            << "   Interface MTU:         " << this->m_device->getMtu()
            << std::endl; // get interface MTU

    // get DNS servers
    if (!this->m_device->getDnsServers().empty())
        std::cout << "   DNS server:            " << this->m_device->getDnsServers().at(0) << std::endl;
}

void packet_analyzer::start_capture_for_experiment()
{
    std::cout << std::endl
              << "Starting async capture..." << std::endl;
    bool only_icmp = this->get_monitor_ssh_config();
    if (this->is_monitor_mode)
    {
        ssh_updater ssh_updater(this->ssh_configuration);
        this->m_device->startCapture(this->packet_vector);
        ssh_updater.start_monitor(only_icmp);
    } else
    {
        // start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
        this->m_device->startCapture(this->packet_vector);
    }
}

void packet_analyzer::start_capture()
{
    std::cout << std::endl
              << "Starting async capture..." << std::endl;
    // start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
    this->m_device->startCapture(this->packet_vector);
}

void packet_analyzer::stop_capture(experiment_type type)
{
    std::cout << std::endl
              << "Stopping capture..." << std::endl;
    if (type == SIMPLE_CAPTURE)
    {
        this->m_device->stopCapture();
        packet_analyzer::parse_simple_capture();
        return;
    }

    // stop the capture
    if (this->is_monitor_mode)
    {
        ssh_updater ssh_updater(this->ssh_configuration);
        this->m_device->stopCapture();
        // Stop the monitor and save the pcap file
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
    if (type == ICMP_ECHO)
        packet_analyzer::parse_icmp_echo_packets();
    else if (type == ICMP_TIMESTAMP)
        packet_analyzer::parse_icmp_timestamp_packets();
}

void packet_analyzer::parse_simple_capture()
{
    for (auto &packet: this->packet_vector)
    {
        auto parsedPacket = pcpp::Packet(packet);
        std::cout << "----------------------------------" << std::endl;
        auto duration = std::chrono::seconds{parsedPacket.getRawPacket()->getPacketTimeStamp().tv_sec} +
                        std::chrono::nanoseconds{parsedPacket.getRawPacket()->getPacketTimeStamp().tv_nsec};
        std::cout << "Packet length: " << parsedPacket.getRawPacket()->getRawDataLen() << std::endl;
        std::cout << "Packet timestamp: " << duration.count() << std::endl;
        std::vector<std::string> data;
        parsedPacket.toStringList(data);
        for (auto &line: data)
        {
            std::cout << line << std::endl;
        }
        std::cout << "----------------------------------" << std::endl;
    }
}

void packet_analyzer::parse_icmp_echo_packets()
{
    icmp_echo_analyzer_adapter adapter;
    for (const pcpp::RawPacket &packet: this->packet_vector_4_monitor)
    {
        icmp_echo_analyzer_monitor_packet icmp_packet(packet.getRawData(),
                                                      packet.getRawDataLen(),
                                                      packet.getPacketTimeStamp());

        if (!icmp_packet.is_icmp_packet())
            continue;
        std::cout << "----------------------------------" << std::endl;
        adapter.add_icmp_packet(icmp_packet);
        std::cout << "ICMP " << (icmp_packet.get_icmp_type() == ICMP_ECHO_REQUEST ? "Request" : "Reply") << std::endl;
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
        if (icmpLayer->getIcmpHeader()->type == ICMP_ECHO_REQUEST)
        {
            icmp_echo_analyzer_monitor_packet icmp_packet(iter->getRawData(),
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

            adapter.change_echo_icmp_captured_time(ICMP_ECHO_REQUEST, id, sequence, duration);
        } else if (icmpLayer->getIcmpHeader()->type == ICMP_ECHO_REPLY)
        {
            auto duration = std::chrono::seconds{parsedPacket.getRawPacket()->getPacketTimeStamp().tv_sec} +
                            std::chrono::nanoseconds{parsedPacket.getRawPacket()->getPacketTimeStamp().tv_nsec};
            auto id = __bswap_constant_16(icmpLayer->getEchoReplyData()->header->id);
            auto sequence = __bswap_constant_16(icmpLayer->getEchoReplyData()->header->sequence);
            adapter.change_echo_icmp_captured_time(ICMP_ECHO_REPLY, id, sequence, duration);
        }
    }
    std::cout << std::endl
              << "Differences between ICMP packets: " << std::endl;
    std::vector<std::pair<icmp_echo_analyzer_monitor_packet, icmp_echo_analyzer_monitor_packet>> icmp_packets = adapter.get_icmp_req_rep_list();
    for (std::pair<icmp_echo_analyzer_monitor_packet, icmp_echo_analyzer_monitor_packet> packet: icmp_packets)
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
                packet.second.get_captured_time() - packet.first.get_captured_time())
                            .count() /
                    1000;
        float diff_f = diff / 1000.0;

        tabulate::Table difference;
        std::stringstream ss_diff;
        ss_diff << std::dec << std::setprecision(6) << diff_f;
        table.add_row({"Difference", ss_diff.str() + " ms", ss_diff.str() + " ms"});
        table.format().font_align(tabulate::FontAlign::center);
        table.row(6).format().multi_byte_characters(true);
        std::cout << table << std::endl
                  << std::endl
                  << std::endl;
    }
    // Export to CSV
    packet_analyzer::export_to_csv(icmp_packets);
}

void packet_analyzer::parse_icmp_timestamp_packets()
{
    icmp_timestamp_analyzer_adapter adapter;
    for (const pcpp::RawPacket &packet: this->packet_vector_4_monitor)
    {
        icmp_timestamp_analyzer_monitor_packet icmp_ts_packet(packet.getRawData(), packet.getRawDataLen(),
                                                              packet.getPacketTimeStamp());
        if (!icmp_ts_packet.is_icmp_packet())
            continue;
        adapter.add_icmp_packet(icmp_ts_packet);
        std::cout << "----------------------------------" << std::endl;
        std::cout << "ICMP Timestamp "
                  << (icmp_ts_packet.get_icmp_type() == ICMP_TIMESTAMP_REQUEST ? "Request" : "Reply")
                  << std::endl;
        std::cout << "Signal strength: " << icmp_ts_packet.get_signal_strength() << std::endl;
        std::cout << "Sequence number: " << icmp_ts_packet.get_sequence_number() << std::endl;
        std::stringstream ss;
        ss << std::hex << icmp_ts_packet.get_id_number();
        std::cout << "ID number: 0x" << ss.str() << " | " << icmp_ts_packet.get_id_number() << std::endl;
        std::cout << "Origin timestamp: " << icmp_ts_packet.get_orig_ts().count() << std::endl;
        std::cout << "Receive timestamp: " << icmp_ts_packet.get_received_ts().count() << std::endl;
        std::cout << "Transmit timestamp: " << icmp_ts_packet.get_transmit_ts().count() << std::endl;
        std::cout << "WLAN duration: " << icmp_ts_packet.get_wlan_duration() << " µs" << std::endl;
        std::cout << "----------------------------------" << std::endl;
    }
    for (auto &rawPacket: this->packet_vector)
    {
        pcpp::Packet parsedPacket(rawPacket);
        if (!parsedPacket.isPacketOfType(pcpp::ICMP))
        {
            continue;
        }
        auto *icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
        if (icmpLayer->getIcmpHeader()->type == ICMP_TIMESTAMP_REQUEST)
        {
            auto *icmpTimestampRequest = icmpLayer->getTimestampRequestData();
            std::cout << "----------------------------------" << std::endl;
            std::cout << "ICMP Timestamp Request" << std::endl;

            // Need to swap the bytes for id, sequence, orig_ts, receive_ts and transmit_ts because they are in network byte order
            auto id = __bswap_constant_16(icmpTimestampRequest->id);
            auto sequence = __bswap_constant_16(icmpTimestampRequest->sequence);
            std::cout << "Sequence number: " << sequence
                      << std::endl;

            std::cout << "ID number: " << id << std::endl;
            auto orig_ts = std::chrono::nanoseconds{__bswap_constant_32(icmpTimestampRequest->originateTimestamp)};
            auto receive_ts = std::chrono::nanoseconds{__bswap_constant_32(icmpTimestampRequest->receiveTimestamp)};
            auto transmit_ts = std::chrono::nanoseconds{__bswap_constant_32(icmpTimestampRequest->transmitTimestamp)};
            std::cout << "Origin timestamp: " << orig_ts.count()
                      << std::endl;
            std::cout << "Receive timestamp: " << receive_ts.count()
                      << std::endl;
            std::cout << "Transmit timestamp: " << transmit_ts.count()
                      << std::endl;
            auto captured_ts = std::chrono::seconds{parsedPacket.getRawPacket()->getPacketTimeStamp().tv_sec} +
                               std::chrono::nanoseconds{parsedPacket.getRawPacket()->getPacketTimeStamp().tv_nsec};
            std::cout << "Captured timestamp: " << captured_ts.count()
                      << std::endl;
            adapter.change_timestamp_icmp_captured_time(ICMP_TIMESTAMP_REQUEST, id, sequence, captured_ts);
            adapter.change_timestamp_icmp_orig_ts(id, sequence, orig_ts);
            adapter.change_timestamp_icmp_received_ts(id, sequence, receive_ts);
            adapter.change_timestamp_icmp_transmit_ts(id, sequence, transmit_ts);
            std::cout << "----------------------------------" << std::endl;
        } else if (icmpLayer->getIcmpHeader()->type == ICMP_TIMESTAMP_REPLY)
        {
            auto *icmpTimestampReply = icmpLayer->getTimestampReplyData();
            auto id = __bswap_constant_16(icmpTimestampReply->id);
            auto sequence = __bswap_constant_16(icmpTimestampReply->sequence);
            auto captured_ts = std::chrono::seconds{parsedPacket.getRawPacket()->getPacketTimeStamp().tv_sec} +
                               std::chrono::nanoseconds{parsedPacket.getRawPacket()->getPacketTimeStamp().tv_nsec};
            auto orig_ts = std::chrono::nanoseconds{__bswap_constant_32(icmpTimestampReply->originateTimestamp)};
            auto receive_ts = std::chrono::nanoseconds{__bswap_constant_32(icmpTimestampReply->receiveTimestamp)};
            auto transmit_ts = std::chrono::nanoseconds{__bswap_constant_32(icmpTimestampReply->transmitTimestamp)};
            std::cout << "----------------------------------" << std::endl;
            std::cout << "ICMP Timestamp Reply" << std::endl;
            std::cout << "Sequence number: " << sequence << std::endl;
            std::cout << "ID number: " << id << std::endl;
            std::cout << "Origin timestamp: " << orig_ts.count()
                      << std::endl;
            std::cout << "Receive timestamp: " << receive_ts.count()
                      << std::endl;
            std::cout << "Transmit timestamp: " << transmit_ts.count()
                      << std::endl;

            std::cout << "Captured timestamp: " << captured_ts.count()
                      << std::endl;
            adapter.change_timestamp_icmp_captured_time(ICMP_TIMESTAMP_REPLY, id, sequence, captured_ts);
            adapter.change_timestamp_icmp_orig_ts(id, sequence, orig_ts);
            adapter.change_timestamp_icmp_received_ts(id, sequence, receive_ts);
            adapter.change_timestamp_icmp_transmit_ts(id, sequence, transmit_ts);
            std::cout << "----------------------------------" << std::endl;
        }
    }
    std::cout << "Printing ICMP Timestamps" << std::endl;
    std::vector<std::pair<icmp_timestamp_analyzer_monitor_packet, icmp_timestamp_analyzer_monitor_packet>> timestamp_packets =
            adapter.get_icmp_ts_req_rep_list();
    for (std::pair<icmp_timestamp_analyzer_monitor_packet, icmp_timestamp_analyzer_monitor_packet> packet: timestamp_packets)
    {
        tabulate::Table table;
        table.add_row({"ICMP Timestamp Type", "ID", "Sequence", "Originate Timestamp", "Receive Timestamp",
                       "Transmit Timestamp",
                       "Captured Time", "Signal Strength", "WLAN Duration"});
        std::stringstream ss_id;
        ss_id << packet.first.get_id_number() << " | 0x" << std::hex << packet.first.get_id_number();
        table.add_row({"Request",
                       ss_id.str(),
                       std::to_string(packet.first.get_sequence_number()),
                       std::to_string(packet.first.get_orig_ts().count()),
                       std::to_string(packet.first.get_received_ts().count()),
                       std::to_string(packet.first.get_transmit_ts().count()),
                       std::to_string(packet.first.get_captured_time().count()),
                       std::to_string(packet.first.get_signal_strength()),
                       std::to_string(packet.first.get_wlan_duration())});
        table.add_row({"Reply",
                       ss_id.str(),
                       std::to_string(packet.second.get_sequence_number()),
                       std::to_string(packet.second.get_orig_ts().count()),
                       std::to_string(packet.second.get_received_ts().count()),
                       std::to_string(packet.second.get_transmit_ts().count()),
                       std::to_string(packet.second.get_captured_time().count()),
                       std::to_string(packet.second.get_signal_strength()),
                       std::to_string(packet.second.get_wlan_duration())});
        table.format().font_align(tabulate::FontAlign::center);
        std::cout << table << std::endl;
    }
    // Export to CSV
    packet_analyzer::export_to_csv(timestamp_packets);
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

void packet_analyzer::get_hw_address(const std::string &ip_address, pcpp::MacAddress &hw_address)
{
    // Send an ARP request to get the MAC address of the target
    pcpp::EthLayer ethLayer(this->m_device->getMacAddress(), pcpp::MacAddress("ff:ff:ff:ff:ff:ff"), PCPP_ETHERTYPE_ARP);
    pcpp::ArpLayer arpLayer(pcpp::ARP_REQUEST, this->m_device->getMacAddress(), pcpp::MacAddress("ff:ff:ff:ff:ff:ff"),
                            this->m_device->getIPv4Address(),
                            pcpp::IPv4Address(ip_address));
    pcpp::Packet arpPacket(42);
    arpPacket.addLayer(&ethLayer);
    arpPacket.addLayer(&arpLayer);
    arpPacket.computeCalculateFields();
    this->m_device->sendPacket(&arpPacket);
    this->m_device->startCaptureBlockingMode(on_packet_arrives, &hw_address, 1000);
}

void
packet_analyzer::start_icmp_echo_experiment(const std::string &target_ip, int nb_packets, int packet_size, int interval)
{

    pcpp::MacAddress hw_address_to_ping;
    this->get_hw_address(target_ip, hw_address_to_ping);

    std::cout << "MAC address to ping: " << hw_address_to_ping << std::endl;
    // Start capture
    this->start_capture_for_experiment();
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

        pcpp::IcmpLayer icmpLayer;

        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::high_resolution_clock::now().time_since_epoch());
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
        auto nanoseconds_only = duration - std::chrono::seconds(seconds);
        auto timestamp = seconds << 32 | nanoseconds_only.count();

        icmpLayer.setEchoRequestData(seq_id, i, __bswap_constant_64(timestamp), data, packet_size + 6);

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
    this->stop_capture(ICMP_ECHO);
}

void packet_analyzer::start_icmp_timestamp_experiment(const std::string &target_ip, int nb_packets,
                                                      int interval)
{
    pcpp::MacAddress hw_address_to_ping;
    this->get_hw_address(target_ip, hw_address_to_ping);

    std::cout << "MAC address to ping: " << hw_address_to_ping << std::endl;
    // Start capture
    this->start_capture_for_experiment();
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

        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now().time_since_epoch());
        auto today = std::chrono::duration_cast<std::chrono::days>(duration);
        auto time_since_midnight = duration - today; // Time in UTC

        pcpp::IcmpLayer icmpLayer;
        timeval tv{time_since_midnight.count() / 1000, (time_since_midnight.count() % 1000) * 1000};

        icmpLayer.setTimestampRequestData(seq_id, i, tv);
        pcpp::Packet icmp_timestamp(54);
        icmp_timestamp.addLayer(&ethLayer4icmp);
        icmp_timestamp.addLayer(&ipLayer4icmp);
        icmp_timestamp.addLayer(&icmpLayer);
        icmp_timestamp.computeCalculateFields();

        this->m_device->sendPacket(&icmp_timestamp);
        std::this_thread::sleep_for(std::chrono::milliseconds(interval));
    }
    // Stop capture
    pcpp::multiPlatformSleep(1);
    this->stop_capture(ICMP_TIMESTAMP);
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

void packet_analyzer::export_to_csv(
        std::vector<std::pair<icmp_echo_analyzer_monitor_packet, icmp_echo_analyzer_monitor_packet>> &icmp_packets,
        const std::string &file_name)
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

void packet_analyzer::export_to_csv(
        std::vector<std::pair<icmp_timestamp_analyzer_monitor_packet, icmp_timestamp_analyzer_monitor_packet>> &timestamp_packets,
        const std::string &file_name)
{
    std::ofstream csv_file(file_name);
    csv_file
            << "ICMP_Timestamp_type,Identifier,Sequence,Captured_timestamp,Originate_timestamp,Receive_timestamp,Transmit_timestamp,Signal_strength,WLAN_duration"
            << std::endl;
    for (auto &timestamp_packet: timestamp_packets)
    {
        auto timestamp_request = timestamp_packet.first;
        auto timestamp_reply = timestamp_packet.second;
        csv_file << timestamp_request.get_icmp_type() << "," << timestamp_request.get_id_number() << ","
                 << timestamp_request.get_sequence_number()
                 << "," << timestamp_request.get_captured_time().count() << ","
                 << timestamp_request.get_orig_ts().count()
                 << "," << timestamp_request.get_received_ts().count() << ","
                 << timestamp_request.get_transmit_ts().count() << ","
                 << timestamp_request.get_signal_strength() << ","
                 << timestamp_request.get_wlan_duration() << std::endl;

        csv_file << timestamp_reply.get_icmp_type() << "," << timestamp_reply.get_id_number() << ","
                 << timestamp_reply.get_sequence_number()
                 << "," << timestamp_reply.get_captured_time().count() << ","
                 << timestamp_reply.get_orig_ts().count()
                 << "," << timestamp_reply.get_received_ts().count() << ","
                 << timestamp_reply.get_transmit_ts().count() << ","
                 << timestamp_reply.get_signal_strength() << ","
                 << timestamp_reply.get_wlan_duration() << std::endl;
    }
    csv_file.close();
}
