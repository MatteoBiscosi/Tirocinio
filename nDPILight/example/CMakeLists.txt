cmake_minimum_required(VERSION 3.16)
project(nDPILight)

set(CMAKE_CXX_STANDARD 11)
SET(CMAKE_CXX_FLAGS -pthread)

# add extra include directories
include_directories(SYSTEM ./src/src/include/ndpi_include SYSTEM ./src/src/include SYSTEM ./src/include)


# add extra lib directories
link_directories(./src/src/lib/ndpi_lib ./src/src/lib ./src/lib)




add_executable(nDPILight nDPILight.cpp src/include/ndpi_light_includes.h src/include/reader.h src/lib/pcap_reader.cpp
                src/lib/napatech_reader.cpp src/include/pcap_reader.h src/include/napatech_reader.h
                src/include/reader_thread.h src/lib/reader_thread.cpp src/include/flow_info.h src/lib/flow_info.cpp)



find_package(PCAP REQUIRED)
MESSAGE( [Main] " PCAP_INCLUDE_DIR = ${PCAP_INCLUDE_DIR}")
MESSAGE( [Main] " PCAP_LIBRARY = ${PCAP_LIBRARY}")

#[Main] PCAP_INCLUDE_DIR = /usr/include
#[Main] PCAP_LIBRARY = /usr/lib/x86_64-linux-gnu/libpcap.so