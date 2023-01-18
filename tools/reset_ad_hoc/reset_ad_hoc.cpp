//
// Created by Kevin on 17/01/2023.
//

#include "reset_ad_hoc.h"

void reset_ad_hoc(){

    // Stop the wireless interface
    system("sudo ifconfig wlan0 down");

    // Restore the old configuration file
    system("sudo cp /etc/network/interfaces.bak /etc/network/interfaces");

    // Restart the network
    system("sudo ifconfig wlan0 up");
    system("sudo /etc/init.d/networking restart");

    // Print the old network settings
    std::cout << "Old network settings:" << std::endl;
    system("cat /etc/network/interfaces");

    // Reboot the raspberry pi after 10 seconds
    std::cout << std::endl << "Done! Reboot in 10 sec" << std::endl;
    sleep(10);
    system("sudo reboot");

}