cmake_minimum_required(VERSION 3.16.3)
project(platform)

set(CMAKE_CXX_STANDARD 20)

add_executable(platform main.cpp main.h tools/setup_ad_hoc/setup_ad_hoc.cpp tools/setup_ad_hoc/setup_ad_hoc.h tools/reset_ad_hoc/reset_ad_hoc.cpp tools/reset_ad_hoc/reset_ad_hoc.h tools/config/config.cpp tools/config/config.h)

add_subdirectory(extern/cxxopts)
target_include_directories(${PROJECT_NAME} PUBLIC cxxopts)
target_link_libraries(${PROJECT_NAME} PUBLIC cxxopts)
