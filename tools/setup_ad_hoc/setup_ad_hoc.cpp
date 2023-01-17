//
// Created by Kevin on 17/01/2023.
//

#include "setup_ad_hoc.h"

void setup_ad_hoc(const std::string& ssid, const std::string& ip, const std::string& channel){

    // Create the new configuration file
    std::ofstream newConfig;
    newConfig.open("interfaces.adhoc", std::ios::trunc);
    newConfig << "auto lo" << std::endl;
    newConfig << "iface lo inet loopback" << std::endl;
    newConfig << "iface eth0 inet dhcp" << std::endl;
    newConfig << "allow-hotplug wlan0" << std::endl;
    newConfig << "iface wlan0 inet static" << std::endl;
    newConfig << "address " << ip << std::endl;
    newConfig << "netmask 255.255.255.0" << std::endl;
    newConfig << "wireless-channel " << channel << std::endl;
    newConfig << "wireless-essid " << ssid << std::endl;
    newConfig << "wireless-mode ad-hoc" << std::endl;
    newConfig.close();

    std::ifstream adhoc_file("interfaces.adhoc");

    // Check if the setup has already been done
    if (check_setup_already_done(adhoc_file)) {
        std::cout << "Setup already done. Skipping setup." << std::endl;
        return;
    }

    system("sudo ifconfig wlan0 down");


    // Backup the old configuration file
    system("sudo cp /etc/network/interfaces /etc/network/interfaces.bak");

    // Change the network settings to ad-hoc mode
    system("sudo mv interfaces.adhoc /etc/network/interfaces");
    // Restart the network
    system("sudo ifconfig wlan0 up");
    system("sudo /etc/init.d/networking restart");
    // Print the new network settings
    std::cout << "New network settings:" << std::endl;
    system("cat /etc/network/interfaces");

    std::cout << std::endl << "Done! Reboot in 10 sec" << std::endl;
    sleep(10);
    system("sudo reboot");
}

bool check_setup_already_done(std::ifstream &adhoc_file){
    std::ifstream interface_file("/etc/network/interfaces");
    std::string str;
    if (interface_file.tellg() != adhoc_file.tellg()){
        return false;
    }
    interface_file.seekg(0, std::ifstream ::beg);
    adhoc_file.seekg(0, std::ofstream::beg);
    return std::equal(std::istreambuf_iterator<char>(interface_file.rdbuf()),
                      std::istreambuf_iterator<char>(),
                      std::istreambuf_iterator<char>(adhoc_file.rdbuf()));
}
