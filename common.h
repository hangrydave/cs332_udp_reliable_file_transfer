//
// Created by david on 10/30/21.
//

#ifndef UDP_RFT_COMMON_H
#define UDP_RFT_COMMON_H

#include <arpa/inet.h>
#include <chrono>

#define PACKET_HEADER_SIZE 13
#define PACKET_BODY_SIZE 1450
#define PACKET_TOTAL_SIZE PACKET_HEADER_SIZE + PACKET_BODY_SIZE

#define ACK_RECEIVE_TIMEOUT 1000            // milliseconds
#define ACK_SIZE 8

#pragma pack(push, 1)
struct s_packet_header {
    // I use int32_t to remind myself that these are 4 bytes each
    uint32_t connection_id;
    uint32_t total_file_size;
    uint32_t packet_num;
    uint8_t ack; // 0 = don't ack, 1 = ack
};
#pragma pack(pop)
static_assert(sizeof(s_packet_header) == PACKET_HEADER_SIZE, "s_packet_header != PACKET_HEADER_SIZE");

#pragma pack(push, 1)
struct s_ack {
    uint32_t connection_id;
    uint32_t packet_num;
};
#pragma pack(pop)
static_assert(sizeof(s_ack) == ACK_SIZE, "s_ack != ACK_SIZE");

/** Convert a char* to an int. Returns the converted number or -1 if an error occurred. **/
int string_to_int(char* const& s) {
    try {
        int num = std::stoi( s );
        return num;
    } catch (std::invalid_argument) {
        return -1;
    }
}

void get_printable_ip_addr(const sockaddr_in& addr, char*& buffer) {
    int buffer_size = INET_ADDRSTRLEN;
    buffer = new char[buffer_size];
    inet_ntop(AF_INET, &addr.sin_addr, buffer, buffer_size);
}

uint32_t get_current_millisecond() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

void debug(const char* msg, const char trailing = '\0') {
#if VERBOSE
    std::cout << msg;
    if (trailing)
        std::cout << trailing;
#endif
}

void debug(const long& msg, const char trailing = '\0') {
#if VERBOSE
    std::cout << msg;
    if (trailing)
        std::cout << trailing;
#endif
}

#endif //UDP_RFT_COMMON_H
