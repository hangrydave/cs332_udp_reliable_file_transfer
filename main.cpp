#include <iostream>
#include <fstream>
#include <limits>
#include <unistd.h>
/*#include <sys/socket.h>
#include <netinet/in.h>*/
#include <memory.h>
#include "common.h"

void send_file(char* const& host, const int& port_number, char* const& file_buffer, const size_t& file_length) {
    std::cout << "Sending " << file_length << " bytes to " << host << "..." << std::endl;

    // useful reference for this stuff:
    // https://people.cs.rutgers.edu/~pxk/417/notes/sockets/udp.html
    // also:
    // http://beej.us/guide/bgnet/
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    sockaddr_in receiver_addr {};
    socklen_t receiver_addr_len = sizeof(receiver_addr);

    // interesting stack oveflow post on the (void*) cast here:
    // https://stackoverflow.com/questions/16534628/in-c-is-casting-to-void-not-needed-inadvisable-for-memcpy-just-as-it-is-not
    memset((void*) &receiver_addr, 0, sizeof(receiver_addr));
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_port = htons(port_number);

    // might need this later
    // receiver_addr.sin_addr.s_addr = INADDR_ANY;

    // set timeout for acks
    timeval tv {};
    tv.tv_sec = ACK_RECEIVE_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv, sizeof(tv));

    size_t packet_count = file_length / PACKET_BODY_SIZE;
    size_t leftover_byte_count = (file_length % PACKET_BODY_SIZE);
    if (leftover_byte_count > 0)
        packet_count++; // make sure we count those leftover bytes

    size_t sent_total_len = 0;
    size_t packet_size = PACKET_BODY_SIZE;
    for (size_t packet_index = 0; packet_index < packet_count; packet_index++) {
        if (packet_index == packet_count - 1 && leftover_byte_count > 0) {
            // if this is the last packet and there are any leftover bytes, then this is the leftover byte packet
            packet_size = leftover_byte_count;
        }

        // assemble the packet
        char* packet_buffer = new char[packet_size];
        size_t base_index = packet_index * PACKET_BODY_SIZE;
        for (size_t byte_index = 0; byte_index < packet_size; byte_index++) {
             size_t actual_byte_index = base_index + byte_index;
             char byte = file_buffer[actual_byte_index];
             packet_buffer[byte_index] = byte;
        }

        // send the packet
        int sent_len = sendto(socket_fd, packet_buffer, packet_size, 0, (sockaddr*) &receiver_addr, sizeof(receiver_addr));
        sent_total_len += sent_len;
        debug("Sent ");
        debug(sent_len);
        debug(" bytes to ");
        debug(host, '\n');

        // listen for an ack
        char ack_buffer[ACK_LEN];
        int received_len = recvfrom(socket_fd, ack_buffer, sizeof(ack_buffer), 0, (sockaddr*) &receiver_addr, &receiver_addr_len);
        if (received_len == -1) {
            // timeout!
            std::cout << "\nTimeout waiting for packet receipt confirmation from " << host << "; exiting" << std::endl;
            return;
        } else if (received_len == ACK_LEN) {
            debug("Received ACK", '\n');
        } else {
            // ?????
        }
    }

    std::cout << "\nFinished sending; sent " << sent_total_len << " over " << packet_count << " packets." << std::endl;
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
    int port_num = std::stoi(port_num_arg);

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

    send_file(host_address_arg, port_num, file_buffer, file_length);
    return 0;
}
