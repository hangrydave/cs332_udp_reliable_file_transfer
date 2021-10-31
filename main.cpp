#include <iostream>
#include <fstream>
#include <limits>
#include <unistd.h>
#include <memory.h>
#include <chrono>
#include <cstring>
#include "common.h"

struct s_sender_state {

};

uint32_t get_connection_id() {
    uint32_t id = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    return id;
}

void setup_socket(
        int port,
        int& socket_fd,
        sockaddr_in& receiver_addr,
        socklen_t& receiver_addr_len) {
    // useful reference for this stuff:
    // https://people.cs.rutgers.edu/~pxk/417/notes/sockets/udp.html
    // also:
    // http://beej.us/guide/bgnet/
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    receiver_addr = {};
    receiver_addr_len = sizeof(receiver_addr);

    // interesting stack oveflow post on the (void*) cast here:
    // https://stackoverflow.com/questions/16534628/in-c-is-casting-to-void-not-needed-inadvisable-for-memcpy-just-as-it-is-not
    memset((void*) &receiver_addr, 0, sizeof(receiver_addr));
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_port = htons(port);

    // might need this later
    // receiver_addr.sin_addr.s_addr = INADDR_ANY;

    // set timeout for acks
    timeval tv {};
    tv.tv_sec = ACK_RECEIVE_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv, sizeof(tv));
}

int send_packet(
        char* const& file_buffer,
        int file_size,
        int packet_index,
        int packet_body_size,
        uint32_t connection_id,
        int socket_fd,
        const sockaddr_in& receiver_addr,
        const socklen_t& receiver_addr_len,
        long& total_sent_len) {
    // assemble the packet
    char* packet_buffer = new char[PACKET_HEADER_SIZE + packet_body_size];

    // cast the first bytes in packet_buffer to a s_packet_header and set the values
    s_packet_header* header = reinterpret_cast<s_packet_header*>(packet_buffer);
    header->connection_id = connection_id;
    header->packet_num = packet_index;
    header->total_file_size = file_size;

    // fill the body area of the buffer
    size_t base_index = packet_index * PACKET_BODY_SIZE;
    for (size_t byte_index = 0; byte_index < packet_body_size; byte_index++) {
        size_t actual_byte_index = base_index + byte_index;
        char byte = file_buffer[actual_byte_index];
        packet_buffer[PACKET_HEADER_SIZE + byte_index] = byte;
    }

    // send the packet
    return sendto(socket_fd, packet_buffer, packet_body_size, 0, (sockaddr*) &receiver_addr, sizeof(receiver_addr));
}

bool get_ack(int connection_id, int packet_num, int socket_fd, const sockaddr_in& receiver_addr, socklen_t& receiver_addr_len) {
    // listen for an ack
//    char ack_buffer[ACK_SIZE];
    s_ack ack;
    int received_len = recvfrom(socket_fd, (void*) &ack, ACK_SIZE, 0, (sockaddr*) &receiver_addr, &receiver_addr_len);
//    if (received_len == ACK_LEN &&
//        ack_buffer[0] == ACK[0] &&
//        ack_buffer[1] == ACK[1] &&
//        ack_buffer[2] == ACK[2]) {
    if (ack.packet_num == packet_num &&
        ack.connection_id == connection_id) {
        debug("ACK received: packet_num=");
        debug(ack.packet_num);
        debug(", connection_id=");
        debug(ack.connection_id, '\n');
        return true;
    } else if (received_len == -1) {
        // timeout!
    } else {
        // ?????
        std::cout << "\nWARNING: SOMETHING SPOOKY HAPPENED (VERY SCARY!!!)" << std::endl;
    }
    return false;
}

void send_file(char* const& host, const int& port, char* const& file_buffer, const size_t& file_size) {
    std::cout << "Sending " << file_size << " bytes to " << host << "..." << std::endl;

    // setup socket
    int socket_fd;
    sockaddr_in receiver_addr;
    socklen_t receiver_addr_len;
    setup_socket(port, socket_fd, receiver_addr, receiver_addr_len);

    // grab a unique connection id
    uint32_t connection_id = get_connection_id();

    // do some math to figure out packet counts and leftover bytes
    size_t packet_count = file_size / PACKET_BODY_SIZE;
    size_t leftover_byte_count = (file_size % PACKET_BODY_SIZE);
    if (leftover_byte_count > 0)
        packet_count++; // make sure we count those leftover bytes

    long total_sent_len = 0;
    size_t packet_size = PACKET_TOTAL_SIZE;
    for (size_t packet_index = 0; packet_index < packet_count; packet_index++) {
        if (packet_index == packet_count - 1 && leftover_byte_count > 0) {
            // if this is the last packet and there are any leftover bytes, then this is the leftover byte packet
            packet_size = PACKET_HEADER_SIZE + leftover_byte_count;
        }

        // for clarity's sake
        int packet_num = packet_index;

        int sent_count = send_packet(
                file_buffer,
                file_size,
                packet_num,
                packet_size,
                connection_id,
                socket_fd,
                receiver_addr,
                receiver_addr_len,
                total_sent_len);

        total_sent_len += sent_count;
        debug("Sent ");
        debug(sent_count);
        debug(" bytes", '\n');

        // get ack
        bool got_ack = get_ack(connection_id, packet_num, socket_fd, receiver_addr, receiver_addr_len);
        if (got_ack) {
//            debug("Received ACK", '\n');
        } else {
            std::cout << "\nTimeout waiting for packet receipt confirmation; exiting" << std::endl;
            break;
        }
    }

    std::cout << "\nFinished sending; sent " << total_sent_len << " over " << packet_count << " packets." << std::endl;
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
