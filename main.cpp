#include <iostream>
#include <fstream>
#include <limits>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <memory.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <errno.h>
#include <stdlib.h>

#define PACKET_SIZE 1450

// input is null terminated
long read_num_from_chars(char* char_arr) {
    // Potential approach: https://stackoverflow.com/a/2797823

    char* end;
    return std::strtol(char_arr, &end, 10);
}

int resolvehelper(char* hostname, int family, char* service, sockaddr_storage* pAddr)
{
    int result;
    struct addrinfo* result_list;
    struct addrinfo hints = {};
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM; // without this flag, getaddrinfo will return 3x the number of addresses (one for each socket type).
    result = getaddrinfo(hostname, service, &hints, &result_list);
    if (result == 0)
    {
        //ASSERT(result_list->ai_addrlen <= sizeof(sockaddr_in));
        memcpy(pAddr, result_list->ai_addr, result_list->ai_addrlen);
        freeaddrinfo(result_list);
    }

    return result;
}

void setup_socket(char* const& hostname, char* const& port_number, int& sock, sockaddr*& addr, size_t& addr_size) {

}

void send(char* const& hostname, char* const& port_number, char* const& file_buffer, const size_t& file_length) {
    // https://stackoverflow.com/questions/24559909/sending-string-over-udp-in-c
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    sockaddr_in addrListen = {}; // zero-int, sin_port is 0, which picks a random port for bind.
    addrListen.sin_family = AF_INET;
    int result = bind(sock, (sockaddr*)&addrListen, sizeof(addrListen));
    if (result == -1)
    {
        int lasterror = errno;
        std::cout << "error: " << lasterror;
        exit(1);
    }

    sockaddr_storage addrDest = {};
    result = resolvehelper(hostname, AF_INET, port_number, &addrDest);
    if (result != 0)
    {
        int lasterror = errno;
        std::cout << "error: " << lasterror;
        exit(1);
    }

    size_t packet_count = file_length / PACKET_SIZE;
    size_t leftover_byte_count = file_length % PACKET_SIZE;
    if (leftover_byte_count > 0)
        packet_count++;

    for (size_t packet_index = 0; packet_index < packet_count; packet_index++) {
        size_t packet_size;
        if (packet_index == packet_count - 1) {
            packet_size = leftover_byte_count;
        } else {
            packet_size = PACKET_SIZE;
        }

        char* packet_buffer = new char[packet_size];
        size_t base_index = packet_index * packet_size;
        for (size_t byte_index = 0; byte_index < packet_size; byte_index++) {
             size_t actual_byte_index = base_index + byte_index;
             packet_buffer[byte_index] = file_buffer[actual_byte_index];
        }

        int result = sendto(sock, packet_buffer, packet_size, 0, (sockaddr*) &addrDest, sizeof(addrDest));
        std::cout << result << " bytes sent" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc > 4) {
        std::cout << "You provided too many arguments; only the first 2 will be used.\n";
    }

    if (argc < 4) {
        std::cout << "Not enough arguments provided; please provide a host address, a port number, and a file path." << std::endl;
        return 1;
    }

    // host address
    char* host_address_arg = argv[1];
    std::string host_address(host_address_arg);

    // port num
    char* port_num_arg = argv[2];
    long port_num = read_num_from_chars(port_num_arg);
    std::cout << port_num << std::endl;

    // file path
    char* file_path_arg = argv[3];
    std::string path(file_path_arg);
    std::fstream file_stream(path, std::ios::in | std::ios::binary);

    // https://stackoverflow.com/a/22986486/5132781
    file_stream.ignore(std::numeric_limits<std::streamsize>::max());
    std::streamsize file_length = file_stream.gcount();
    file_stream.clear();
    file_stream.seekg(0, std::ios_base::beg);

    char* file_buffer = new char[file_length];
    file_stream.read(file_buffer, file_length);

    send(host_address_arg, port_num_arg, file_buffer, file_length);
    return 0;
}
