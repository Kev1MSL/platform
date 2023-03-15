cmake_minimum_required(VERSION 3.16.3)
project(platform)

set(CMAKE_CXX_STANDARD 20)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(libssh REQUIRED)
find_package(jsoncpp REQUIRED)
find_package(PcapPlusPlus REQUIRED)
if (NOT TARGET ssh)
    add_library(ssh SHARED IMPORTED)
    set_target_properties(ssh
            PROPERTIES
            IMPORTED_LOCATION "${LIBSSH_LIBRARIES}"
            INTERFACE_INCLUDE_DIRECTORIES "${LIBSSH_INCLUDE_DIR}")
endif ()

add_executable(
        platform main.cpp main.h
        tools/setup_ad_hoc/setup_ad_hoc.cpp
        tools/setup_ad_hoc/setup_ad_hoc.h
        tools/reset_ad_hoc/reset_ad_hoc.cpp
        tools/reset_ad_hoc/reset_ad_hoc.h
        tools/config/config.cpp
        tools/config/config.h
        tools/set_monitor_mode/set_monitor_mode.cpp
        tools/set_monitor_mode/set_monitor_mode.h
        tools/propagate_update/propagate_update.cpp
        tools/propagate_update/propagate_update.h
        tools/packet_analyzer/packet_analyzer.cpp
        tools/packet_analyzer/packet_analyzer.h tools/packet_analyzer/icmp_analyzer.cpp tools/packet_analyzer/icmp_analyzer.h tools/rfi_generator/rfi_generator.cpp tools/rfi_generator/rfi_generator.h)

add_subdirectory(extern/cxxopts)
add_subdirectory(extern/tabulate)
add_subdirectory(extern/libtins)
target_include_directories(${PROJECT_NAME} PUBLIC cxxopts tabulate libtins)
target_link_libraries(${PROJECT_NAME} PUBLIC cxxopts jsoncpp ssh PcapPlusPlus::PcapPlusPlus tabulate libtins)