//
// Created by Kevin Messali on 20/02/23.
//

#ifndef PLATFORM_ICMP_ANALYZER_H
#define PLATFORM_ICMP_ANALYZER_H

#include <cstdlib>
#include <chrono>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

/// @brief Type of the ICMP packet (echo request, echo reply, timestamp request, timestamp reply).
enum icmp_type
{
    ICMP_ECHO_REQUEST = 0x8,
    ICMP_ECHO_REPLY = 0x0,
    ICMP_TIMESTAMP_REQUEST = 0xd,
    ICMP_TIMESTAMP_REPLY = 0xe,
    NOT_ICMP
};

// TODO: Make a general class for monitoring packet and inherit from it

/// @brief Class that represents a packet captured by the monitor RPI. The monitored data is completed by the platform RPI. This class is used for the ICMP echo experiment.
class icmp_echo_analyzer_monitor_packet
{
public:
    /// @brief Constructor for the icmp_echo_analyzer_monitor_packet class, to be used when the packet is captured by the monitor RPI.
    /// @param raw_data Pointer to the raw data of the packet.
    /// @param raw_data_len Length of the raw data.
    /// @param timestamp Capture time of the packet.
    icmp_echo_analyzer_monitor_packet(const uint8_t *raw_data, int raw_data_len, timespec timestamp);

    /// @brief Constructor for the icmp_echo_analyzer_monitor_packet class.
    icmp_echo_analyzer_monitor_packet();

    /// @brief Get a byte from the raw data of the packet.
    /// @param offset The offset of the byte to get.
    /// @return The byte at the given offset.
    uint8_t get_byte_from_packet(int offset);

    /// @brief Get a vector of bytes from the raw data of the packet.
    /// @param begin_offset The offset of the first byte to get.
    /// @param end_offset The offset of the last byte to get not included.
    /// @return The vector of bytes from the range [begin_offset, end_offset[.
    std::vector<uint8_t>
    get_bytes_from_packet(int begin_offset, int end_offset);

    /// @brief Beautify the captured UNIX timestamp into readable date.
    /// @return The date in the format "DD/MM/YYYY HH:MM:SS.xxx".
    std::string print_time_captured();

    /// @brief Beautify the ICMP sent UNIX timestamp into readable date.
    /// @return The date in the format "DD/MM/YYYY HH:MM:SS.xxx".
    std::string print_time_icmp_sent();

    /// @brief Check if the packet is an ICMP packet.
    /// @return True if the packet is an ICMP packet, false otherwise.
    bool is_icmp_packet();

    /// @brief Get the type of the ICMP packet.
    /// @return The type of the ICMP packet.
    [[nodiscard]] icmp_type get_icmp_type() const;

    /// @brief Get the signal strength of the packet from the RadioTap header.
    /// @return The signal strength of the packet received.
    [[nodiscard]] int get_signal_strength() const;

    /// @brief Get the sequence number of the packet.
    /// @return The sequence number of the packet as an integer.
    [[nodiscard]] int get_sequence_number() const;

    /// @brief Get the id number of the packet.
    /// @return The id number of the packet.
    [[nodiscard]] int get_id_number() const;

    /// @brief Get the duration of the packet, i.e. the time the interface blocked itself/the channel to process the packet.
    /// @return The duration of the packet in microseconds.
    [[nodiscard]] uint32_t get_wlan_duration() const;

    /// @brief Get the sent time of the request ICMP packet.
    /// @return The sent time of the requst ICMP packet in a chrono::duration object.
    [[nodiscard]] std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> get_sent_time() const;

    /// @brief Get the captured time of the ICMP packet.
    /// @return The captured time of the ICMP packet in a chrono::duration object.
    [[nodiscard]] std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> get_captured_time() const;

    /// @brief Get the length of the raw data of the packet.
    /// @return The length of the raw data of the packet.
    [[nodiscard]] int get_data_len() const;

    /// @brief Set the sent time of the request ICMP packet from the platform RPI. It will replace the sent time of the monitor RPI, which might be wrong.
    /// @param time The sent time of the request ICMP packet in a chrono::duration object.
    void set_sent_time(std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> time);

    /// @brief Set the captured time of the ICMP packet from the platform RPI. It will replace the captured time of the monitor RPI, which is wrong.
    /// @param time The captured time of the ICMP packet in a chrono::duration object.
    void set_captured_time(std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> time);

private:
    /// @brief Type of the ICMP packet
    icmp_type icmpType;

    /// @brief Signal strength of the packet
    int signal_strength;

    /// @brief Sequence number of the packet
    int sequence_number;

    /// @brief Id number of the packet
    int id_number;

    /// @brief Sent time of the request ICMP packet
    std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> sent_time{};

    /// @brief Captured time of the ICMP packet
    std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> captured_time{};

    /// @brief Duration of the packet that blocked the interface/channel
    uint32_t wlan_duration;

    /// @brief Raw data of the packet
    const uint8_t *raw_data;

    /// @brief Length of the raw data of the packet
    int raw_data_len;
};

/// @brief Adapter class that allows to store and retrieve ICMP icmp_echo_analyzer_monitor_packet. It is used to store the ICMP packets received by the monitor RPI and to retrieve them when the platform RPI needs them.
class icmp_echo_analyzer_adapter
{
public:
    /// @brief Constructor for the icmp_echo_analyzer_adapter class. It will initialize the list of ICMP icmp_echo_analyzer_monitor_packet.
    icmp_echo_analyzer_adapter();

    /// @brief Add an echo ICMP packet to the list of ICMP packets.
    /// @param icmp_packet The ICMP echo packet to add.
    void add_icmp_packet(const icmp_echo_analyzer_monitor_packet &icmp_packet);

    /// @brief Get the pair of ICMP echo packets (reply/request) corresponding to the given sequence.
    /// @param sequence_number The sequence number of the ICMP echo packets to get.
    /// @return The pair of ICMP echo packets (reply/request) corresponding to the given sequence.
    std::pair<icmp_echo_analyzer_monitor_packet, icmp_echo_analyzer_monitor_packet>
    get_icmp_req_rep(int sequence_number);

    /// @brief Get the list of ICMP echo pair packets (reply/request).
    /// @return Return the list of ICMP echo pair packet indexed by the sequence number and making sure to have pairs, i.e. ignoring timeouts, etc.
    std::vector<std::pair<icmp_echo_analyzer_monitor_packet, icmp_echo_analyzer_monitor_packet>>
    get_icmp_req_rep_list();

    /// @brief Change the sent time of the request ICMP echo packets in both the pair of ICMP packets (reply/request) corresponding to the given sequence.
    /// @param id_number The id number of the ICMP echo packets to change.
    /// @param sequence_number The sequence number of the ICMP echo packets to change.
    /// @param time The new sent time of the request ICMP echo packet in a chrono::duration object.
    void change_echo_icmp_req_rep_time(int id_number, int sequence_number,
                                       std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> time);

    /// @brief Change the captured time of the ICMP echo packet to the given time from the platform RPI.
    /// @param type The type of the ICMP echo packet to change.
    /// @param id_number The id number of the ICMP echo packet to change.
    /// @param sequence_number The sequence number of the ICMP echo packet to change.
    /// @param time The new captured time of the ICMP echo packet in a chrono::duration object.
    void change_echo_icmp_captured_time(icmp_type type, int id_number, int sequence_number,
                                        std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> time);

    ~icmp_echo_analyzer_adapter();

private:
    /// @brief List of ICMP packets
    std::vector<icmp_echo_analyzer_monitor_packet> icmp_packet_list;
};

/// @brief Class that represents a packet captured by the monitor RPI. The monitored data is completed by the platform RPI. This class is used for the ICMP echo timestamp experiment.
class icmp_timestamp_analyzer_monitor_packet
{
public:
    /// @brief Contructor for the icmp_timestamp_analyzer_monitor_packet class, to be used when the packet is received by the monitor RPI.
    /// @param raw_data A pointer to the raw data of the packet.
    /// @param raw_data_len The length of the raw data of the packet.
    /// @param timestamp The captured timestamp of the packet.
    icmp_timestamp_analyzer_monitor_packet(const uint8_t *raw_data, int raw_data_len, timespec timestamp);

    /// @brief Contructor for the icmp_timestamp_analyzer_monitor_packet class, to be used when the packet is received by the platform RPI.
    icmp_timestamp_analyzer_monitor_packet();

    /// @brief Get a byte from the raw data of the packet.
    /// @param offset The offset of the byte to get.
    /// @return The byte at the given offset.
    uint8_t get_byte_from_packet(int offset);

    /// @brief Get a vector of bytes from the raw data of the packet.
    /// @param begin_offset The offset of the first byte to get.
    /// @param end_offset The offset of the last byte to get not included.
    /// @return The vector of bytes from the range [begin_offset, end_offset[.
    std::vector<uint8_t>
    get_bytes_from_packet(int begin_offset, int end_offset);

    /// @brief Beautify the captured UNIX timestamp into readable date.
    /// @return The date in the format "DD/MM/YYYY HH:MM:SS.xxx".
    std::string print_time_captured();

    /// @brief Beautify the ICMP sent UNIX timestamp into readable date.
    /// @return The date in the format "DD/MM/YYYY HH:MM:SS.xxx".
    std::string print_time_icmp_sent();

    /// @brief Check if the packet is an ICMP packet.
    /// @return True if the packet is an ICMP packet, false otherwise.
    bool is_icmp_packet();

    /// @brief Get the type of the ICMP packet.
    /// @return The type of the ICMP packet.
    [[nodiscard]] icmp_type get_icmp_type() const;

    /// @brief Get the signal strength of the packet from the RadioTap header.
    /// @return The signal strength of the packet received.
    [[nodiscard]] int get_signal_strength() const;

    /// @brief Get the sequence number of the packet.
    /// @return The sequence number of the packet as an integer.
    [[nodiscard]] int get_sequence_number() const;

    /// @brief Get the id number of the packet.
    /// @return The id number of the packet.
    [[nodiscard]] int get_id_number() const;

    /// @brief Get the duration of the packet, i.e. the time the interface blocked itself/the channel to process the packet.
    /// @return The duration of the packet in microseconds.
    [[nodiscard]] uint32_t get_wlan_duration() const;

    /// @brief Get the originate time of the request ICMP timestamp packet.
    /// @return The originate time of the requst ICMP packet in a chrono::duration object.
    [[nodiscard]] std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> get_orig_ts() const;

    /// @brief Get the received time of the request ICMP timestamp packet.
    /// @return The received time of ICMP timestamp packet in a chrono::duration object.
    [[nodiscard]] std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> get_received_ts() const;

    /// @brief Get the transmit time of the replay ICMP timestamp packet.
    /// @return The transmit time of reply ICMP timestamp packet in a chrono::duration object.
    [[nodiscard]] std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> get_transmit_ts() const;

    /// @brief Get the captured time of the packet.
    /// @return The captured time of the packet in a chrono::duration object.
    [[nodiscard]] std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> get_captured_time() const;

    /// @brief Get the length of the raw data of the packet.
    [[nodiscard]] int get_data_len() const;

    /// @brief Set the originate time of the request ICMP timestamp packet.
    /// @param time The new originate time of the request ICMP timestamp packet in a chrono::duration object.
    void set_orig_ts(std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> time);

    /// @brief Set the received time of the request ICMP timestamp packet.
    /// @param time The new received time of the request ICMP timestamp packet in a chrono::duration object.
    void set_received_ts(std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> time);

    /// @brief Set the transmit time of the reply ICMP timestamp packet.
    /// @param time The new transmit time of the reply ICMP timestamp packet in a chrono::duration object.
    void set_transmit_ts(std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> time);

    /// @brief Set the captured time of the ICMP packet.
    /// @param time The new captured time of the ICMP packet in a chrono::duration object.
    void set_captured_time(std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> time);

private:
    /// @brief Type of the ICMP packet.
    icmp_type icmpType;

    /// @brief Signal strength of the packet.
    int signal_strength;

    /// @brief Sequence number of the packet.
    int sequence_number;

    /// @brief Id number of the packet.
    int id_number;

    /// @brief Originate time of the request ICMP timestamp packet.
    std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> orig_ts{};

    /// @brief Received time of the request ICMP timestamp packet.
    std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> received_ts{};

    /// @brief Transmit time of the reply ICMP timestamp packet.
    std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> transmit_ts{};

    /// @brief Captured time of the packet.
    std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> captured_time{};

    /// @brief Duration of the packet.
    uint32_t wlan_duration;

    /// @brief Raw data of the packet.
    const uint8_t *raw_data;

    /// @brief Length of the raw data of the packet.
    int raw_data_len;
};

/// @brief Adapter class that allows to store and retrieve ICMP icmp_timestamp_analyzer_monitor_packet. It is used to store the ICMP packets received by the monitor RPI and to retrieve them when the platform RPI needs them.
class icmp_timestamp_analyzer_adapter
{
public:
    /// @brief Constructor of the icmp_timestamp_analyzer_adapter class. It will initialize the list of ICMP icmp_timestamp_analyzer_monitor_packet.
    icmp_timestamp_analyzer_adapter();

    /// @brief Add an ICMP timestamp packet to the list of ICMP packets.
    /// @param icmp_packet The ICMP timestamp packet to add to the list.
    void add_icmp_packet(const icmp_timestamp_analyzer_monitor_packet &icmp_packet);

    /// @brief Get the pair of ICMP timestamp packets (reply/request) corresponding to the given sequence.
    /// @param sequence_number The sequence number of the ICMP timestamp packets to get.
    /// @return The pair of ICMP timestamp packets (reply/request) corresponding to the given sequence.
    std::pair<icmp_timestamp_analyzer_monitor_packet, icmp_timestamp_analyzer_monitor_packet>
    get_icmp_ts_req_rep(int sequence_number);

    /// @brief Get the list of ICMP timestamp pair packets (reply/request).
    /// @return Return the list of ICMP timestamp pair packet indexed by the sequence number and making sure to have pairs, i.e. ignoring timeouts, etc.
    std::vector<std::pair<icmp_timestamp_analyzer_monitor_packet, icmp_timestamp_analyzer_monitor_packet>>
    get_icmp_ts_req_rep_list();

    /// @brief Change the captured time of the ICMP timestamp packet to the given time from the platform RPI.
    /// @param type The type of the ICMP timestamp packet to change.
    /// @param id_number The id number of the ICMP timestamp packet to change.
    /// @param sequence_number The sequence number of the ICMP timestamp packet to change.
    /// @param time The new captured time of the ICMP timestamp packet in a chrono::duration object.
    void change_timestamp_icmp_captured_time(icmp_type type, int id_number, int sequence_number,
                                             std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> time);

    /// @brief Change the originate time of the ICMP timestamp request packet.
    /// @param id_number The id number of the ICMP timestamp request packet to change.
    /// @param sequence_number The sequence number of the ICMP request timestamp packet to change.
    /// @param time The new originate time of the ICMP timestamp request packet in a chrono::duration object.
    void change_timestamp_icmp_orig_ts(int id_number, int sequence_number,
                                       std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> time);

    /// @brief Change the received time of the ICMP timestamp request packet on the other device.
    /// @param id_number The id number of the ICMP timestamp reply packet to change.
    /// @param sequence_number The sequence number of the ICMP reply timestamp packet to change.
    /// @param time The new received time of the ICMP timestamp reply packet in a chrono::duration object.
    void change_timestamp_icmp_received_ts(int id_number, int sequence_number,
                                           std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> time);

    /// @brief Change the transmit time of the ICMP timestamp reply packet.
    /// @param id_number The id number of the ICMP timestamp reply packet to change.
    /// @param sequence_number The sequence number of the ICMP reply timestamp packet to change.
    /// @param time The new transmit time of the ICMP timestamp reply packet in a chrono::duration object.
    void change_timestamp_icmp_transmit_ts(int id_number, int sequence_number,
                                           std::chrono::duration<uint64_t, std::ratio<1, 1000000000>> time);

    ~icmp_timestamp_analyzer_adapter();

private:
    /// @brief List of ICMP timestamp packets.
    std::vector<icmp_timestamp_analyzer_monitor_packet> icmp_packet_list;
};

#endif // PLATFORM_ICMP_ANALYZER_H
