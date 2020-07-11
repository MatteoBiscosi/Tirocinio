cmake_minimum_required(VERSION 3.16)
project(nDPIRevision)

set(CMAKE_CXX_STANDARD 11)

add_executable(nDPIRevision ndpiSimpleIntRevised.cpp lib/workflow.cpp lib/flow.cpp lib/workflow.h tmp.cpp)