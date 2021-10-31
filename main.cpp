#include <iostream>
#include <fstream>
#include <limits>
#include <unistd.h>
#include <memory.h>
#include <chrono>
#include "common.h"

#define SUCCESS_ACK 0
#define ERROR_ACK_TIMEOUT -1
#define ERROR_ACK_OTHER -2

struct s_sender_resources {
    size_t file_size;
    int socket_fd;
    int connection_id;
    sockaddr_in receiver_addr;
    socklen_t receiver_addr_len;
};

uint32_t get_connection_id() {
    uint32_t id = get_current_millisecond();
    return id;
}

void setup_resources(int port, s_sender_resources& resources) {
    resources = {};

    // grab a unique connection id
    resources.connection_id = get_connection_id();

    // useful reference for networking stuff:
    // https://people.cs.rutgers.edu/~pxk/417/notes/sockets/udp.html
    // also:
    // http://beej.us/guide/bgnet/
    resources.socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    sockaddr_in receiver_addr = {};
    resources.receiver_addr_len = sizeof(receiver_addr);

    // interesting stack overflow post on the (void*) cast here:
    // https://stackoverflow.com/questions/16534628/in-c-is-casting-to-void-not-needed-inadvisable-for-memcpy-just-as-it-is-not
    memset((void*) &receiver_addr, 0, sizeof(receiver_addr));
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_port = htons(port);

    resources.receiver_addr = receiver_addr;

    // set timeout for acks
    timeval tv {};
    tv.tv_sec = ACK_RECEIVE_TIMEOUT / 1000;
    tv.tv_usec = 0;
    setsockopt(resources.socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv, sizeof(tv));
}

int send_packet(
        char* const& file_buffer,
        uint32_t file_size,
        int packet_index,
        int packet_body_size,
        bool request_ack,
        const s_sender_resources& resources,
//        uint32_t connection_id,
//        int socket_fd,
//        const sockaddr_in& receiver_addr,
//        const socklen_t& receiver_addr_len,
        long& total_sent_len) {
    // assemble the packet
    char* packet_buffer = new char[PACKET_HEADER_SIZE + packet_body_size];

    // cast the first bytes in packet_buffer to a s_packet_header and set the values
    s_packet_header* header = reinterpret_cast<s_packet_header*>(packet_buffer);
    header->connection_id = resources.connection_id;
    header->packet_num = packet_index;
    header->total_file_size = file_size;
    header->ack = request_ack;

    debug("packet header: ");
    debug("connection_id=");
    debug(header->connection_id);
    debug(", packet_num=");
    debug(header->packet_num);
    debug(", total_file_size=");
    debug(header->total_file_size);
    debug(", ack=");
    debug(header->ack, '\n');

    // fill the body area of the buffer
    size_t base_index = packet_index * PACKET_BODY_SIZE;
    for (size_t byte_index = 0; byte_index < packet_body_size; byte_index++) {
        size_t actual_byte_index = base_index + byte_index;
        char byte = file_buffer[actual_byte_index];
        packet_buffer[PACKET_HEADER_SIZE + byte_index] = byte;
    }

    // send the packet
    return sendto(
            resources.socket_fd,
            packet_buffer,
            packet_body_size,
            0,
            (sockaddr*) &resources.receiver_addr,
            sizeof(resources.receiver_addr));
}

int get_ack(int packet_num, s_sender_resources& resources) {
    s_ack ack;
    int received_len = recvfrom(
            resources.socket_fd,
            (void*) &ack,
            ACK_SIZE,
            0,
            (sockaddr*) &resources.receiver_addr,
            &resources.receiver_addr_len);

    if (ack.packet_num == packet_num &&
        ack.connection_id == resources.connection_id) {
        debug("ACK received: packet_num=");
        debug(ack.packet_num);
        debug(", connection_id=");
        debug(ack.connection_id, '\n');
        return SUCCESS_ACK;
    } else if (received_len == -1) {
        // timeout!
        return ERROR_ACK_TIMEOUT;
    }
    // ?????
    return ERROR_ACK_OTHER;
}

void send_file(
        char* const& host,
        int port,
        char* const& file_buffer,
        size_t file_size) {
    std::cout << "Sending " << file_size << " bytes to " << host << "..." << std::endl;

    // setup socket
    s_sender_resources resources;
//    int socket_fd;
//    sockaddr_in receiver_addr;
//    socklen_t receiver_addr_len;
    setup_resources(port, resources);//socket_fd, receiver_addr, receiver_addr_len);

    // ack things
    int ack_gap_counter = 0;
    size_t previously_acked_packet_index = 0;

    // do some math to figure out packet counts and leftover bytes
    size_t packets_to_send_count = file_size / PACKET_BODY_SIZE;
    size_t leftover_byte_count = (file_size % PACKET_BODY_SIZE);
    if (leftover_byte_count > 0)
        packets_to_send_count++; // make sure we count those leftover bytes

    long total_sent_len = 0;
    size_t packet_size = PACKET_TOTAL_SIZE;
    for (size_t packet_index = 0; packet_index < packets_to_send_count; packet_index++) {
        if (packet_index == packets_to_send_count - 1 && leftover_byte_count > 0) {
            // if this is the last packet and there are any leftover bytes, then this is the leftover byte packet
            packet_size = PACKET_HEADER_SIZE + leftover_byte_count;
        }

        // for clarity's sake
        int packet_num = packet_index;

        // does this packet need an ack?
        bool needs_ack = packet_index - previously_acked_packet_index == ack_gap_counter;

        // send the dang thing
        int sent_count = send_packet(
                file_buffer,
                file_size,
                packet_num,
                packet_size,
                needs_ack,
                resources,
//                connection_id,
//                socket_fd,
//                receiver_addr,
//                receiver_addr_len,
                total_sent_len);

        if (sent_count < 0) {
            std::cout << "Error sending packet; exiting" << std::endl;
            exit(1);
        }

        total_sent_len += sent_count;

        debug("Sent ");
        debug(sent_count);
        debug(" bytes", '\n');

        if (needs_ack) {
            // get ack
            int ack_result = get_ack(packet_num, resources);
            switch (ack_result) {
                case SUCCESS_ACK:
                    previously_acked_packet_index = packet_index;
                    ack_gap_counter++;

                    debug("ACK gap=");
                    debug(ack_gap_counter, '\n');
                    break;
                case ERROR_ACK_TIMEOUT:
                    std::cout << "\nTimeout waiting for ACK at packet " << packet_num << std::endl;

                    // revert back to the packet after the previously acked one
                    ack_gap_counter = 0;
                    packet_index = previously_acked_packet_index;
                    debug("Rewinding to packet ");
                    debug(packet_index);
                    debug(" and resetting ack_gap_counter to 0", '\n');
                    break;
                case ERROR_ACK_OTHER:
                    std::cout << "\nWARNING: SOMETHING SPOOKY HAPPENED (VERY SCARY!!!)" << std::endl;
                    break;
            }
        }
    }

    std::cout << "\nFinished sending; sent " << file_size << " bytes over " << packets_to_send_count << " packets." << std::endl;
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
