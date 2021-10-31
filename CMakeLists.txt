cmake_minimum_required(VERSION 3.17)
project(udp_reliable_file_transfer)

set(CMAKE_CXX_STANDARD 14)

add_executable(rft_sender rft_sender/rft_sender.cpp common.h)
add_executable(rft_receiver rft_receiver/rft_receiver.cpp common.h)