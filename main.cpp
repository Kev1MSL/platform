#include "main.h"

int main(int argc, char *argv[])
{
    std::cout << std::endl
              << "Welcome on the platform test wireless routing protocols" << std::endl
              << std::endl;

    // Use cxxopts to parse the arguments
    cxxopts::Options options("platform", "");
    options.add_options()
            ("h,help", "Print this help message")
            ("a,adhoc_setup", "Change the Raspberry PI network settings to ad-hoc mode",
             cxxopts::value<std::vector<std::string>>(),
             "<ssid> <ip> <number of channels>")
            ("r,adhoc_reset",
             "Reset the Raspberry PI network settings to default")
            ("m,monitor_setup", "Set up the interface into monitor mode", cxxopts::value<std::string>(),
             "<interface>")
            ("s,start", "Start a protocol", cxxopts::value<std::string>(), "<protocol>")
            ("c,config",
             "Configure an option of the Raspberry PI wireless card",
             cxxopts::value<bool>(),
             "<option>");
    options.add_options("Packet analysis")
            ("P,print", "Print info for an interface", cxxopts::value<std::string>(), "<interface>")
            ("C,capture", "Capture packets on an interface",
             cxxopts::value<std::string>(), "<interface>")
            ("l,launch", "Launch ping experiment", cxxopts::value<std::string>(),
             "<interface> <target_ip> <number of packets> <packet size> <interval>")
            ("t,timestamp", "Launch timestamp experiment", cxxopts::value<std::string>(),
             "<interface> <target_ip> <number of packets> <interval>");
    options.add_options("Propagate remote operations")
            ("p,propagate", "Propagate updates of files in directory over the network",
             cxxopts::value<std::vector<std::string>>(),
             "<interface to use> <platform's directory>")
            ("i,install",
             "Install a package on the Raspberry PI",
             cxxopts::value<std::vector<std::string>>(),
             "<interface to use> <package name(s)>")
            ("S,send", "Send files to the Raspberry PI", cxxopts::value<std::vector<std::string>>(),
             "<interface to use> <from directory> <to directory> \"<file(s)>\"")
            ("R,run",
             "Run command on all the Raspberry PIs",
             cxxopts::value<std::vector<std::string>>(),
             "<interface to use> <command>")
            ("T,ntp", "Set the Raspberry PI ntp server", cxxopts::value<std::string>(),
             "<interface to use> <ntp server ip>");
    options.add_options("List of configuration")
            ("rate", "Set the bit rate", cxxopts::value<std::string>(), "<rate>")
            ("tx", "Set the transmitting power", cxxopts::value<std::string>(), "<power in dBm or mW>")(
            "sensitivity",
            "Set the threshold for sensitivity",
            cxxopts::value<std::string>(),
            "<threshold>");

    options.allow_unrecognised_options();
    if (argc < 2)
    {
        std::cout << options.help() << std::endl;
        exit(1);
    }
    cxxopts::ParseResult result;
    try
    {
        result = options.parse(argc, argv);
    }
    catch (cxxopts::exceptions::exception &e)
    {
        std::cout << "error parsing options: " << e.what() << std::endl;

        std::cout << options.help() << std::endl;
        exit(1);
    }

    // Print help message
    if (result.count("help"))
    {
        std::cout << options.help() << std::endl;
        exit(0);
    }

    // Configure the wireless card in ad-hoc mode
    if (result.count("adhoc_setup"))
    {
        std::cout << "-- Setup ad-hoc network --" << std::endl
                  << std::endl;
        std::vector<std::string> adhoc_setup = result["adhoc_setup"].as<std::vector<std::string>>();
        std::vector<std::string> unmatched = result.unmatched();
        adhoc_setup.insert(adhoc_setup.end(), unmatched.begin(), unmatched.end());
        if (adhoc_setup.size() != 3)
        {
            std::cout << "ERROR: Missing arguments." << std::endl;
            std::cout << "Usage: " << argv[0] << " --adhoc_setup <ssid> <ip> <number of channels>" << std::endl;
            exit(1);
        }
        setup_ad_hoc(adhoc_setup[0], adhoc_setup[1], adhoc_setup[2]);
    }

    // Reset the wireless card to default
    if (result.count("adhoc_reset"))
    {
        std::cout << "-- Reset ad-hoc network --" << std::endl
                  << std::endl;
        std::ifstream adhoc_file("/etc/network/interfaces.bak");
        if (!adhoc_file.good())
        {
            std::cout << "No backup file found, exiting..." << std::endl;
            exit(1);
        }
        reset_ad_hoc();
    }

    // Configure a wireless card to monitor mode
    if (result.count("monitor_setup"))
    {
        std::cout << "-- Setup monitor mode --" << std::endl
                  << std::endl;
        std::string iface = result["monitor_setup"].as<std::string>();
        const std::vector<std::string> &unmatched = result.unmatched();
        if (!unmatched.empty())
        {
            std::cout << "ERROR: Too many arguments." << std::endl;
            std::cout << "Usage: " << argv[0] << " --monitor_setup <interface>" << std::endl;
            exit(1);
        }
        set_monitor_mode(iface);
    }

    // Propagate updates of the platform C++ project over the network, by installing the right libraries offline, transferring the project files and compiling them
    if (result.count("propagate"))
    {
        std::cout << "-- Propagate update --" << std::endl
                  << std::endl;
        std::vector<std::string> p_arg = result["propagate"].as<std::vector<std::string>>();
        std::vector<std::string> unmatched = result.unmatched();
        p_arg.insert(p_arg.end(), unmatched.begin(), unmatched.end());
        if (p_arg.size() != 2)
        {
            std::cout << "ERROR: Missing arguments." << std::endl;
            std::cout << "Usage: " << argv[0] << " --propagate <interface to use> <platform's directory>" << std::endl;
            exit(1);
        }
        std::string iface = p_arg[0];
        std::string dir = p_arg[1];
        if (dir[dir.size() - 1] == '/')
            dir = dir.substr(0, dir.size() - 1);
        std::vector<ssh_config> config = get_ssh_config(dir);
        if (config.empty())
        {
            std::cout << "ERROR: Unable to get the configuration of the Raspberry PI." << std::endl;
            exit(1);
        }

        // Get the current IP address to skip it when propagating the update
        std::string ip = get_ip_address(iface);

        for (auto &i: config)
        {
            if (i.host == ip)
            {
                std::cout << "Skip " << ip << " because it is the current host." << std::endl;
                continue;
            }
            std::cout << "Begin to propagate update on " << i.host << std::endl;
            ssh_updater updater = ssh_updater(i);
            if (updater.run_update(i.path) != 0)
            {
                std::cout << "ERROR: Unable to propagate update on " << i.host << std::endl;
            } else
            {
                std::cout << "Update successfully propagated on " << i.host << std::endl;
            }
        }
    }

    // Install package(s) on all Raspberry PIs on the network by downloading them and their dependencies locally and then installing it offline on the remote Raspberry PIs
    if (result.count("install"))
    {
        std::cout << "-- Install a package --" << std::endl
                  << std::endl;
        std::vector<std::string> iface = result["install"].as<std::vector<std::string>>();
        const std::vector<std::string> &packages = result.unmatched();
        std::vector<ssh_config> config = get_ssh_config();
        if (packages.empty())
        {
            std::cout << "ERROR: Missing arguments." << std::endl;
            std::cout << "Usage: " << argv[0] << " --install <interface> <package(s)>" << std::endl;
            exit(1);
        }
        if (config.empty())
        {
            std::cout << "ERROR: Unable to get the configuration of the Raspberry PI." << std::endl;
            exit(1);
        }
        std::string ip = get_ip_address(iface[0]);

        for (auto &i: config)
        {
            if (i.host == ip)
            {
                std::cout << "Skip " << ip << " because it is the current host." << std::endl;
                continue;
            }
            std::cout << "Begin to propagate install package(s) on " << i.host << std::endl;
            ssh_updater updater = ssh_updater(i);
            if (updater.install_packages(packages) != 0)
            {
                std::cout << "ERROR: Unable to propagate install package(s) on " << i.host << std::endl;
            } else
            {
                std::cout << "Package(s) installation successfully propagated on " << i.host << std::endl;
            }
        }
    }

    // Send files to all the Raspberry PIs on the network
    if (result.count("send"))
    {
        std::cout << "-- Send files --" << std::endl
                  << std::endl;
        std::string iface = result["send"].as<std::vector<std::string>>()[0];
        std::vector<std::string> unmatched = result.unmatched();
        if (unmatched.size() != 3)
        {
            std::cout << "ERROR: Missing arguments." << std::endl;
            std::cout << "Usage: " << argv[0]
                      << " --send <interface to use> <from directory> <to directory> \"<file(s)>\"" << std::endl;
            exit(1);
        }
        std::string from_dir = unmatched[0];
        std::string to_dir = unmatched[1];
        std::vector<std::string> files = split(unmatched[2]);
        if (from_dir.ends_with("/"))
        {
            from_dir = from_dir.substr(0, from_dir.size() - 1);
        }
        if (to_dir.ends_with("/"))
        {
            to_dir = to_dir.substr(0, to_dir.size() - 1);
        }
        // In case of /* we need to add all files from the directory
        add_files_from_dir(&files, from_dir);
        std::cout << files.size() << " files to send." << std::endl;
        std::vector<ssh_config>
                config = get_ssh_config();
        if (config.empty())
        {
            std::cout << "ERROR: Unable to get the configuration of the Raspberry PI." << std::endl;
            exit(1);
        }
        std::string ip = get_ip_address(iface);
        for (auto &i: config)
        {
            if (i.host == ip)
            {
                std::cout << "Skip " << ip << " because it is the current host." << std::endl;
                continue;
            }
            std::cout << "Begin to propagate send files on " << i.host << std::endl;
            ssh_updater updater = ssh_updater(i);
            if (updater.send_files(from_dir, to_dir, files) != 0)
            {
                std::cout << "ERROR: Unable to propagate send files on " << i.host << std::endl;
            } else
            {
                std::cout << "Files successfully propagated on " << i.host << std::endl;
            }
        }
    }

    // Run a command on all the Raspberry PIs on the network
    if (result.count("run"))
    {
        std::cout << "-- Run a command --" << std::endl
                  << std::endl;
        std::string iface = result["run"].as<std::vector<std::string>>()[0];
        std::vector<std::string> unmatched = result.unmatched();
        if (unmatched.size() != 1)
        {
            std::cout << "ERROR: Missing arguments." << std::endl;
            std::cout << "Usage: " << argv[0] << " --run <interface to use> <command>" << std::endl;
            exit(1);
        }
        std::string command;
        for (const auto &i: unmatched)
        {
            command += i + " ";
        }
        std::vector<ssh_config>
                config = get_ssh_config();
        if (config.empty())
        {
            std::cout << "ERROR: Unable to get the configuration of the Raspberry PI." << std::endl;
            exit(1);
        }
        std::string ip = get_ip_address(iface);
        for (auto &i: config)
        {
            if (i.host == ip)
            {
                std::cout << "Skip " << ip << " because it is the current host." << std::endl;
                continue;
            }
            std::cout << "Begin to propagate run command on " << i.host << std::endl;
            ssh_updater updater = ssh_updater(i);
            if (updater.run_command(command) != 0)
            {
                std::cout << "ERROR: Unable to propagate run command on " << i.host << std::endl;
            } else
            {
                std::cout << "Command successfully propagated on " << i.host << std::endl;
            }
        }
    }

    // Set the ntp server on all the Raspberry PIs on the network
    if (result.count("ntp"))
    {
        std::cout << "-- Set the ntp server --" << std::endl
                  << std::endl;
        std::string iface = result["ntp"].as<std::string>();
        std::vector<std::string> unmatched = result.unmatched();
        if (unmatched.size() != 1)
        {
            std::cout << "ERROR: Missing arguments." << std::endl;
            std::cout << "Usage: " << argv[0] << " --ntp <interface to use> <ntp server ip>" << std::endl;
            exit(1);
        }
        std::string ntp_server = unmatched[0];
        std::vector<ssh_config>
                config = get_ssh_config();
        if (config.empty())
        {
            std::cout << "ERROR: Unable to get the configuration of the Raspberry PI." << std::endl;
            exit(1);
        }
        std::string ip = get_ip_address(iface);
        for (auto &i: config)
        {
            if (i.host == ip)
            {
                std::cout << "Skip " << ip << " because it is the current host." << std::endl;
                continue;
            }
            std::cout << "Begin to propagate ntp server on " << i.host << std::endl;
            ssh_updater updater = ssh_updater(i);
            if (updater.set_ntp_server(ntp_server) != 0)
            {
                std::cout << "ERROR: Unable to propagate ntp server on " << i.host << std::endl;
            } else
            {
                std::cout << "Ntp server successfully propagated on " << i.host << std::endl;
            }
        }
    }

    // Print network interface info
    if (result.count("print"))
    {
        std::cout << "-- Print interface info --" << std::endl
                  << std::endl;
        if (!is_root())
        {
            exit(1);
        }
        std::string iface = result["print"].as<std::string>();
        std::cout << "Interface: " << iface << std::endl;
        packet_analyzer analyzer = packet_analyzer(iface);
        analyzer.print_device_info();
    }

    // Start capture on the network interface
    if (result.count("capture"))
    {
        std::cout << "-- Capture packets --" << std::endl
                  << std::endl;
        if (!is_root())
        {
            exit(1);
        }
        std::string iface = result["capture"].as<std::string>();
        std::cout << "Interface: " << iface << std::endl;
        packet_analyzer analyzer = packet_analyzer(iface);
        analyzer.start_capture();
        std::cout << "Press any key to stop the capture." << std::endl;
        std::cin.get();
        analyzer.stop_capture(experiment_type::SIMPLE_CAPTURE);
    }

    // Launch the ping experiment - might require to have an extra RPI in monitor mode to get more data
    if (result.count("launch"))
    {
        std::cout << "-- Launch the ping experiment --" << std::endl
                  << std::endl;
        if (!is_root())
        {
            exit(1);
        }
        std::string iface = result["launch"].as<std::string>();
        std::cout << "Interface: " << iface << std::endl;
        std::vector<std::string> unmatched = result.unmatched();
        if (unmatched.size() != 4)
        {
            std::cout << "ERROR: Missing arguments." << std::endl;
            std::cout << "Usage: " << argv[0]
                      << " --launch <interface> <target_ip> <number of packets> <packet size> <interval in ms>"
                      << std::endl;
            exit(1);
        }
        std::string target_ip = unmatched[0];
        int nb_packets = std::stoi(unmatched[1]);
        int packet_size = std::stoi(unmatched[2]);
        int interval = std::stoi(unmatched[3]);
        packet_analyzer analyzer = packet_analyzer(iface);
        analyzer.start_icmp_echo_experiment(target_ip, nb_packets, packet_size, interval);
    }

    // Start the timestamp experiment - might require to have an extra RPI in monitor mode to get more data
    if (result.count("timestamp"))
    {
        std::cout << "-- Launch the timestamp experiment --" << std::endl
                  << std::endl;
        if (!is_root())
        {
            exit(1);
        }
        std::string iface = result["timestamp"].as<std::string>();
        std::cout << "Interface: " << iface << std::endl;
        std::vector<std::string> unmatched = result.unmatched();
        if (unmatched.size() != 3)
        {
            std::cout << "ERROR: Missing arguments." << std::endl;
            std::cout << "Usage: " << argv[0]
                      << " --timestamp <interface> <target_ip> <number of packets> <interval in ms>"
                      << std::endl;
            exit(1);
        }
        std::string target_ip = unmatched[0];
        int nb_packets = std::stoi(unmatched[1]);
        int interval = std::stoi(unmatched[2]);
        packet_analyzer analyzer = packet_analyzer(iface);
        analyzer.start_icmp_timestamp_experiment(target_ip, nb_packets, interval);
    }

    // Configure the current Raspberry PI's WiFi interface
    if (result.count("config"))
    {
        // Change the bit rate
        if (result.count("rate"))
        {
            std::cout << "-- Set the bit rate --" << std::endl
                      << std::endl;
            std::string rate = result["rate"].as<std::string>();
            change_rate(rate);
        }

        // Change the transmitting power
        if (result.count("tx"))
        {
            std::cout << "-- Set the transmitting power --" << std::endl
                      << std::endl;
            std::string tx = result["tx"].as<std::string>();
            change_tx_power(tx);
        }

        // Change the sensitivity threshold
        if (result.count("sensitivity"))
        {
            std::cout << "-- Set the threshold for sensitivity --" << std::endl
                      << std::endl;
            std::string sensitivity = result["sensitivity"].as<std::string>();
            change_sensitivity(sensitivity);
        }
    } else if (result.count("rate") || result.count("tx") || result.count("sensitivity"))
    {
        std::cout << "ERROR: Missing arguments." << std::endl;
        std::cout << "Usage: " << argv[0] << " --config <option>" << std::endl;
        exit(1);
    }
    return 0;
}

/// @brief Get the ssh configuration of the Raspberry PI from the static/devices.json file.
/// @param path Path to the directory where we want to execute the ssh_updater commands.
/// @return A vector of ssh_configuration containing the configuration of all the Raspberry PIs.
std::vector<ssh_config> get_ssh_config(const std::string &path)
{
    std::ifstream rpi_config_file("static/devices.json");
    if (!rpi_config_file.good())
    {
        std::cout << "ERROR: Unable to open devices.json" << std::endl;
        return {};
    }
    Json::Value rpi_config;
    rpi_config_file >> rpi_config;
    Json::Value rpi_list = rpi_config["RPI_List"];
    std::vector<ssh_config> config_list;
    for (Json::Value::ArrayIndex i = 0; i < rpi_config["nbr_rpi"].asInt(); i++)
    {
        // Skip the Raspberry PI if it is not active, i.e. RPI_STATUS = OFF in the devices.json file
        if (rpi_config["RPI_List"][i]["RPI_STATUS"].asString() == "OFF")
        {
            continue;
        }
        ssh_config config;
        config.host = rpi_config["RPI_List"][i]["RPI_IP"].asString();
        config.username = rpi_config["RPI_List"][i]["RPI_USER"].asString();
        config.password = rpi_config["RPI_List"][i]["RPI_PASS"].asString();
        config.path = path;
        config_list.push_back(config);
    }
    return config_list;
}

/// @brief Get the IP address of the interface.
/// @param iface Interface name to get the IP address from.
/// @return The IPV4 address of the interface.
std::string get_ip_address(const std::string &iface)
{
    // Get the IP address of the interface
    // Original code from https://www.geekpage.jp/en/programming/linux-network/get-ipaddr.php
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr
            {
            };
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    ioctl(sock, SIOCGIFADDR, &ifr);
    close(sock);

    return inet_ntoa(((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr);
}

/// @brief Helper function to split a string into a vector of strings with space delimiter.
/// @param str The string to split.
/// @return A vector of strings splitted on space.
std::vector<std::string> split(const std::string &str)
{
    std::vector<std::string> result;
    std::istringstream iss(str);
    for (std::string s; iss >> s;)
        result.push_back(s);
    return result;
}

bool is_root()
{
    if (geteuid() != 0)
    {
        std::cout << "ERROR: You need to be root to run packet analysis." << std::endl;
        return false;
    }
    return true;
}