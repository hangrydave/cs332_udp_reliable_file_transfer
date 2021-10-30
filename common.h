//
// Created by david on 10/30/21.
//

#ifndef RFT_SENDER_COMMON_H
#define RFT_SENDER_COMMON_H

#define PACKET_SIZE 1450
#define DEBUG true

void debug(const char* msg, const char trailing = NULL) {
    if (!DEBUG)
        return;

    std::cout << msg;
    if (trailing)
        std::cout << trailing;
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
