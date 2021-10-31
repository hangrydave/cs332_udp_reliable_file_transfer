#include <iostream>
#include <fstream>
#include <limits>
#include <unistd.h>
#include <memory.h>
#include <chrono>
#include <netdb.h>
#include "../common.h"

#define ACK_TIMEOUTS_BEFORE_EXIT 5
#define SUCCESS_ACK 0
#define ERROR_ACK_TIMEOUT -1
#define ERROR_ACK_OTHER -2

struct s_sender_resources {
    int file_size;
    int socket_fd;
    int connection_id;
    sockaddr_in receiver_addr;
    socklen_t receiver_addr_len;
    sockaddr_storage receiver_addr_2;
};

/** Get a unique connection id. **/
uint32_t get_connection_id() {
    uint32_t id = get_current_millisecond();
    return id;
}

/** Setup some networking resources. **/
void setup_resources(char* const& host, char* const& port, s_sender_resources& resources) {
    int port_num = string_to_int(port);
    if (port_num < 0) {
        std::cout << "Invalid port given; please provide a valid port number from 1 to 65535" << std::endl;
        exit(1);
    }

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
    receiver_addr.sin_port = htons(port_num);

    resources.receiver_addr = receiver_addr;

    resources.receiver_addr_2 = {};
    addrinfo* result_list = NULL;
    addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    int result = getaddrinfo(host, port, &hints, &result_list);
    if (result == 0)
    {
        memcpy(&resources.receiver_addr_2, result_list->ai_addr, result_list->ai_addrlen);
        freeaddrinfo(result_list);
    } else {
        std::cout << "Encountered error; is \"" << host << "\" a valid hostname?" << std::endl;
        exit(1);
    }

    // set timeout for acks
    timeval tv {};
    tv.tv_sec = ACK_RECEIVE_TIMEOUT / 1000;
    tv.tv_usec = 0;
    setsockopt(resources.socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv, sizeof(tv));
}

/** Send a packet containing a portion of a file's data. **/
int send_packet(
        char* const& file_buffer,
        int packet_index,
        int packet_body_size,
        bool request_ack,
        const s_sender_resources& resources,
        long& total_sent_len) {
    // assemble the packet
    char* packet_buffer = new char[PACKET_HEADER_SIZE + packet_body_size];

    // cast the first bytes in packet_buffer to a s_packet_header and set the values
    s_packet_header* header = reinterpret_cast<s_packet_header*>(packet_buffer);
    header->connection_id = resources.connection_id;
    header->packet_num = packet_index;
    header->total_file_size = resources.file_size;
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
    int base_index = packet_index * PACKET_BODY_SIZE;
    for (int byte_index = 0; byte_index < packet_body_size; byte_index++) {
        int actual_byte_index = base_index + byte_index;
        char byte = file_buffer[actual_byte_index];
        packet_buffer[PACKET_HEADER_SIZE + byte_index] = byte;
    }

    // send the packet
    return sendto(
            resources.socket_fd,
            packet_buffer,
            packet_body_size,
            0,
            (sockaddr*) &resources.receiver_addr_2,
            sizeof(resources.receiver_addr_2));
}

/** Wait for an ACK packet. **/
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
        return ERROR_ACK_TIMEOUT;
    }
    return ERROR_ACK_OTHER;
}

/** Figure out what size a new packet should be. **/
int get_new_packet_size(int packet_index, int packets_to_send_count, int leftover_byte_count) {
    if (packet_index == packets_to_send_count - 1 && leftover_byte_count > 0) {
        // if this is the last packet and there are any leftover bytes, then this is the leftover byte packet
        return PACKET_HEADER_SIZE + leftover_byte_count;
    }
    return PACKET_TOTAL_SIZE;
}

/** Handle an ACK packet coming from the receiver. **/
void handle_ack(
        int& packet_index,
        int& previously_timed_out_ack_packet,
        int& repeated_ack_timeout_counter,
        int& previously_acked_packet_index,
        int& ack_gap_counter,
        s_sender_resources& resources) {
    int ack_result = get_ack(packet_index, resources);
    switch (ack_result) {
        case SUCCESS_ACK:
            previously_acked_packet_index = packet_index;
            ack_gap_counter++;

            debug("ACK gap=");
            debug(ack_gap_counter, '\n');
            break;
        case ERROR_ACK_TIMEOUT:
            if (packet_index == previously_timed_out_ack_packet) {
                repeated_ack_timeout_counter++;
                if (repeated_ack_timeout_counter == ACK_TIMEOUTS_BEFORE_EXIT - 1) {
                    std::cout << "\nFile transfer success unknown" << std::endl;
                    exit(1);
                }
            } else {
                repeated_ack_timeout_counter = 0;
            }

            std::cout << "\nTimeout waiting for ACK at packet " << packet_index << std::endl;

            // revert back to the packet after the previously acked one and reset the counter
            ack_gap_counter = 0;
            previously_timed_out_ack_packet = packet_index;
            packet_index = previously_acked_packet_index - 1;
            debug("Rewinding to packet ");
            debug(packet_index);
            debug(" and resetting ack_gap_counter to 0", '\n');
            break;
        case ERROR_ACK_OTHER:
            debug("unknown error while dealing with ACK", '\n');
            break;
        default:
            break;
    }
}

/** Send a file to a receiver. **/
void send_file(char* const& host, char* const& port, char* const& file_buffer, int file_size) {
    // setup socket
    s_sender_resources resources = {};
    setup_resources(host, port, resources);
    resources.file_size = file_size;

    std::cout << "Sending " << file_size << " bytes to " << host << "..." << std::endl;

    // initialize ack things
    int ack_gap_counter = 0;
    int previously_acked_packet_index = 0;

    int repeated_ack_timeout_counter = 0;
    int previously_timed_out_ack_packet = 0;

    // do some math to figure out packet counts and leftover bytes
    int packets_to_send_count = file_size / PACKET_BODY_SIZE;
    int leftover_byte_count = (file_size % PACKET_BODY_SIZE);
    if (leftover_byte_count > 0)
        packets_to_send_count++; // make sure we count those leftover bytes

    long total_sent_len = 0;
    int packet_size;
    for (int packet_index = 0; packet_index < packets_to_send_count; packet_index++) {
        packet_size = get_new_packet_size(packet_index, packets_to_send_count, leftover_byte_count);

        // does this packet need an ack?
        bool needs_ack =
                packet_index == packets_to_send_count - 1 ||
                packet_index - previously_acked_packet_index == ack_gap_counter;

        // send the dang thing
        int sent_count = send_packet(
                file_buffer,
                packet_index,
                packet_size,
                needs_ack,
                resources,
                total_sent_len);

        if (sent_count < 0) {
            // Houston, we've got a problem
            std::cout << "Error sending packet; exiting" << std::endl;
            exit(1);
        }

        total_sent_len += sent_count;

        debug("Sent ");
        debug(sent_count);
        debug(" bytes", '\n');

        if (needs_ack) {
            // get ack
            handle_ack(
                    packet_index,
                    previously_timed_out_ack_packet,
                    repeated_ack_timeout_counter,
                    previously_acked_packet_index,
                    ack_gap_counter,
                    resources);
        }
    }

    std::cout << "\nFinished sending; sent " << file_size << " bytes over " << packets_to_send_count << " packets." << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
#if VERBOSE
        std::cout << "Usage: rft_sender_verbose <host address> <port number> <file_path>\n\nExample: rft_sender_verbose 127.0.0.1 22222 file_to_send" << std::endl;
#else
        std::cout << "Usage: rft_sender <host address> <port number> <file_path>\n\nExample: rft_sender 127.0.0.1 22222 file_to_send" << std::endl;
#endif
        return 1;
    }

    // host address
    char* host_address_arg = argv[1];
    std::string host_address(host_address_arg);

    // port num
    char* port_num_arg = argv[2];

    // file path
    char* file_path_arg = argv[3];
    std::string path(file_path_arg);
    std::fstream file_stream(path, std::ios::in | std::ios::binary);

    // https://stackoverflow.com/a/22986486/5132781
    file_stream.ignore(std::numeric_limits<std::streamsize>::max());
    std::streamsize file_length = file_stream.gcount();
    file_stream.clear();
    file_stream.seekg(0, std::ios_base::beg);

    if (file_length <= 0) {
        std::cout << "File \"" << path << "\" does not exist" << std::endl;
        return 1;
    }

    char* file_buffer = new char[file_length];
    file_stream.read(file_buffer, file_length);

    send_file(host_address_arg, port_num_arg, file_buffer, file_length);
    return 0;
}
