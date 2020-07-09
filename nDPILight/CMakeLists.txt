cmake_minimum_required(VERSION 3.16)
project(nDPILight)

set(CMAKE_CXX_STANDARD 11)

# add extra include directories
include_directories(SYSTEM /usr/matteo/tirocinio/nDPI/src/include)
include_directories(SYSTEM ./src/src/include)
include_directories(SYSTEM ./src/include)


# add extra lib directories
link_directories(/usr/matteo/tirocinio/nDPI/src/include)
link_directories(./src/src/lib)
link_directories(./src/lib)


add_executable(nDPILight nDPILight.cpp src/include/ndpi_light_includes.h src/include/reader.h src/lib/pcap_reader.cpp src/lib/napatech_reader.cpp src/include/pcap_reader.h src/include/napatech_reader.h src/include/reader_thread.h src/lib/reader_thread.cpp)