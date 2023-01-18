#include "main.h"

int main(int argc, char *argv[]) {
    std::cout << std::endl << "Welcome on the platform test wireless routing protocols" << std::endl << std::endl;
    cxxopts::Options options("platform", "");
    options.add_options()
            ("h,help", "Print this help message")
            ("a,adhoc_setup", "Change the RaspberryPI network settings to ad-hoc mode", cxxopts::value<std::vector<std::string>>(), "<ssid> <ip> <number of channels>")
            ("r,adhoc_reset", "Reset the RaspberryPI network settings to default")
            ("s,start", "Start a protocol", cxxopts::value<std::string>(), "<protocol>")
            ("c,config", "Configure an option of the RaspberryPI wireless card", cxxopts::value<bool>(), "<option>");
    options.add_options("List of configuration")
            ("rate", "Set the bit rate", cxxopts::value<std::string>(), "<rate>")
            ("tx", "Set the transmitting power", cxxopts::value<std::string>(), "<power in dBm or mW>")
            ("sensitivity", "Set the threshold for sensitivity", cxxopts::value<std::string>(), "<threshold>");
    options.allow_unrecognised_options();
    if (argc < 2) {
        std::cout << options.help() << std::endl;
        exit(1);
    }
    cxxopts::ParseResult result;
    try {
        result = options.parse(argc, argv);
    } catch (cxxopts::exceptions::exception &e) {
        std::cout << "error parsing options: " << e.what() << std::endl;

        std::cout << options.help() << std::endl;
        exit(1);
    }

    if (result.count("help")) {
        std::cout << options.help() << std::endl;
        exit(0);
    }

    if (result.count("adhoc_setup")) {
        std::cout << "-- Setup ad-hoc network --" << std::endl << std::endl;
        std::vector<std::string> adhoc_setup = result["adhoc_setup"].as<std::vector<std::string>>();
        std::vector<std::string> unmatched = result.unmatched();
        adhoc_setup.insert(adhoc_setup.end(), unmatched.begin(), unmatched.end());
        if (adhoc_setup.size() != 3) {
            std::cout << "ERROR: Missing arguments." << std::endl;
            std::cout << "Usage: " << argv[0] << " --adhoc_setup <ssid> <ip> <number of channels>" << std::endl;
            exit(1);
        }
        setup_ad_hoc(adhoc_setup[0], adhoc_setup[1], adhoc_setup[2]);
    }

    if (result.count("adhoc_reset")) {
        std::cout << "-- Reset ad-hoc network --" << std::endl << std::endl;
        std::ifstream adhoc_file("/etc/network/interfaces.bak");
        if (!adhoc_file.good()) {
            std::cout << "No backup file found, exiting..." << std::endl;
            exit(1);
        }
        reset_ad_hoc();
    }

    if (result.count("config")) {
        if (result.count("rate")){
            std::cout << "-- Set the bit rate --" << std::endl << std::endl;
            std::string rate = result["rate"].as<std::string>();
            change_rate(rate);
        }
        if (result.count("tx")){
            std::cout << "-- Set the transmitting power --" << std::endl << std::endl;
            std::string tx = result["tx"].as<std::string>();
            change_tx_power(tx);
        }
        if (result.count("sensitivity")){
            std::cout << "-- Set the threshold for sensitivity --" << std::endl << std::endl;
            std::string sensitivity = result["sensitivity"].as<std::string>();
            change_sensitivity(sensitivity);
        }

    }else if (result.count("rate") || result.count("tx") || result.count("sensitivity")){
        std::cout << "ERROR: Missing arguments." << std::endl;
        std::cout << "Usage: " << argv[0] << " --config <option>" << std::endl;
        exit(1);
    }
    return 0;
}