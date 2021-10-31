//
// Created by david on 10/30/21.
//

#ifndef RFT_SENDER_COMMON_H
#define RFT_SENDER_COMMON_H

#include <arpa/inet.h>

#define PACKET_HEADER_SIZE 12
#define PACKET_BODY_SIZE 1450
#define PACKET_TOTAL_SIZE PACKET_HEADER_SIZE + PACKET_BODY_SIZE
#define DEBUG true
#define FILE_PACKET_RECEIVE_TIMEOUT 99999
#define ACK_RECEIVE_TIMEOUT 99999
#define ACK "ACK"
#define ACK_LEN 3

struct s_packet_header {
    // I use int32_t to remind myself that these are 4 bytes each
    uint32_t connection_id;
    int32_t total_file_size;
    int32_t packet_num;
};
static_assert(sizeof(s_packet_header) == PACKET_HEADER_SIZE, "s_packet_header != 12");

void get_printable_ip_addr(const sockaddr_in& addr, char*& buffer) {
    int buffer_size = INET_ADDRSTRLEN;
    buffer = new char[buffer_size];
    inet_ntop(AF_INET, &addr.sin_addr, buffer, buffer_size);
}

void debug(const char* msg, const char trailing = NULL) {
#if DEBUG
    std::cout << msg;
    if (trailing)
        std::cout << trailing;
#endif
}

void debug(const long& msg, const char trailing = NULL) {
    if (!DEBUG)
        return;

    std::cout << msg;
    if (trailing)
        std::cout << trailing;
}

// don't use this please and thank you
// input is null terminated
long read_num_from_chars(char* char_arr) {
    // Potential approach: https://stackoverflow.com/a/2797823

    char* end;
    return std::strtol(char_arr, &end, 10);
}

#endif //RFT_SENDER_COMMON_H
