cmake_minimum_required(VERSION 3.17)
project(udp_reliable_file_transfer)

set(CMAKE_CXX_STANDARD 14)

add_executable(rft_sender rft_sender/rft_sender.cpp common.h)
add_executable(rft_receiver rft_receiver/rft_receiver.cpp common.h)
add_executable(rft_sender_verbose rft_sender/rft_sender.cpp common.h)
add_executable(rft_receiver_verbose rft_receiver/rft_receiver.cpp common.h)

target_compile_definitions(rft_sender PUBLIC DEBUG=0)
target_compile_definitions(rft_receiver PUBLIC DEBUG=0)
target_compile_definitions(rft_sender_verbose PUBLIC DEBUG=1)
target_compile_definitions(rft_receiver_verbose PUBLIC DEBUG=1)
