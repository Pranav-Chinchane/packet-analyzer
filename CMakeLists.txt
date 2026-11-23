cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
find_package(Threads REQUIRED)

add_library(dpi_core
    src/pcap_reader.cpp src/pcap_writer.cpp src/packet_parser.cpp src/types.cpp src/ip_address.cpp src/insights.cpp src/hello_buffer.cpp
    src/name_extractor.cpp src/rules.cpp src/flow_processor.cpp src/report.cpp
    src/cli.cpp src/fast_path.cpp src/load_balancer.cpp src/dpi_engine.cpp)
target_include_directories(dpi_core PUBLIC include)
target_link_libraries(dpi_core PUBLIC Threads::Threads)

add_executable(dpi_simple src/main_simple.cpp)
add_executable(dpi_mt src/main_mt.cpp)
add_executable(unit_tests tests/unit_tests.cpp)
foreach(target dpi_simple dpi_mt unit_tests)
    target_link_libraries(${target} PRIVATE dpi_core)
endforeach()
