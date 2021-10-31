#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <memory.h>
#include "../common.h"

#define FILE_PACKET_RECEIVE_TIMEOUT 1000    // milliseconds
#define TESTING_UNRELIABILITY false

/** Write the data in a char buffer to a file. **/
void write_buffer_to_file(char* const& buffer, const size_t& buffer_size, std::ostream& out) {
    for (int i = 0; i < buffer_size; i++) {
        out << buffer[i];
    }
}

/** Setup the socket. **/
bool setup_socket(int port, int& socket_fd, sockaddr_in& this_addr) {
    // useful reference for this stuff:
    // https://people.cs.rutgers.edu/~pxk/417/notes/sockets/udp.html
    // also:
    // http://beej.us/guide/bgnet/

    this_addr = {};
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    memset((char*) &this_addr, 0, sizeof(this_addr));
    this_addr.sin_family = AF_INET;
    this_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    this_addr.sin_port = htons(port);

    int error = bind(socket_fd, (sockaddr*) &this_addr, sizeof(this_addr));
    if (error < 0) {
        std::cout << "An error was encountered; port " << port << " may be unavailable." << std::endl;
        return false;
    }

    return true;
}

/** Receive a packet from an address. **/
int receive_packet(
        int socket_fd,
        sockaddr_in& remote_addr,
        socklen_t& remote_addr_len,
        char* const& packet_buffer,
        size_t packet_size,
        s_packet_header*& packet_header,
        char*& packet_body_buffer,
        size_t& packet_body_size,
        int& error) {
    int received_packet_size = recvfrom(socket_fd, packet_buffer, packet_size, 0, (sockaddr*) &remote_addr, &remote_addr_len);
    if (received_packet_size == -1) {
        return received_packet_size;
    }

    packet_header = reinterpret_cast<s_packet_header*>(packet_buffer);
    packet_body_buffer = packet_buffer + PACKET_HEADER_SIZE;
    packet_body_size = received_packet_size - PACKET_HEADER_SIZE;

    char* addr_buffer;
    get_printable_address(remote_addr, addr_buffer);
    debug("Received ");
    debug(received_packet_size);
    debug(" bytes in packet #");
    debug(packet_header->packet_num);
    debug(" over connection ");
    debug(packet_header->connection_id);
    debug(" from ");
    debug(addr_buffer, '\n');

    return received_packet_size;
}

/** Send an ACK packet. **/
bool send_ack(int connection_id, int packet_num, int socket_fd, const sockaddr_in& remote_addr) {
    s_ack ack;
    ack.connection_id = connection_id;
    ack.packet_num = packet_num;

    int sent_len = sendto(socket_fd, (void*) &ack, ACK_SIZE, 0, (sockaddr*) &remote_addr, sizeof(remote_addr));
    if (sent_len == 0) {
        return false;
    }

    debug("ACK sent: packet_num=");
    debug(ack.packet_num);
    debug(", connection_id=");
    debug(ack.connection_id, '\n');
    return true;
}

/** Perform some actions on data from a received packet. **/
void handle_packet_data(
        char*& file_buffer,
        int& file_buffer_size,
        int& first_connection_id,
        s_packet_header* const& packet_header,
        int previous_packet_num,
        char* const& packet_body_buffer,
        int packet_body_size,
        bool& ignore_packet) {
    if (file_buffer_size == -1) {
        // the file buffer hasn't been initialized; do that now
        file_buffer_size = packet_header->total_file_size;
        file_buffer = new char[file_buffer_size];
    }

    if (packet_header->packet_num > previous_packet_num + 1) {
        ignore_packet = true; // a future packet? "Great Scott!"
    } else if (packet_header->packet_num == 0 || packet_header->packet_num > previous_packet_num) {
        // copy the bytes from the packet body to the correct spot in the file buffer...
        // ...but ONLY if it's a new packet. no point in doing this for old packets!
        size_t file_buffer_offset = packet_header->packet_num * PACKET_BODY_SIZE;
        memcpy((void*) (file_buffer + file_buffer_offset), (void*) packet_body_buffer, packet_body_size);
    }
}

/** Handle sending or not sending an ACK packet. **/
void handle_ack(int socket_fd, const sockaddr_in& remote_addr, s_packet_header* const& packet_header) {
#if TESTING_UNRELIABILITY
    // In case I need to test the reliability under unreliable conditions.
    // TODO: make more unreliable
    uint32_t current_ms = get_current_millisecond();
    bool should_send_ack = current_ms % 2 == 0;
#elif !TESTING_UNRELIABILITY
    bool should_send_ack = true;
#endif

    if (packet_header->ack && should_send_ack) {
        bool ack_sent_successfully = send_ack(
                packet_header->connection_id,
                packet_header->packet_num,
                socket_fd,
                remote_addr);
        if (!ack_sent_successfully) {
            debug("Error sending ack for packet ");
            debug(packet_header->packet_num, '\n');
        }
    }
}

/** Receive a file on a network port with the UDP protocol. **/
bool receive_file(int port, char*& file_buffer, int& file_size, char*& sender_address_buffer, int& packet_count) {
    // setup the socket
    int socket_fd;
    sockaddr_in this_addr;
    bool success = setup_socket(port, socket_fd, this_addr);
    if (!success) {
        return false;
    }

    std::cout << "Listening on port " << port << "..." << std::endl;

    // initialize useful network things
    sockaddr_in remote_addr = {};
    socklen_t remote_addr_len = sizeof(remote_addr);

    // timeout struct for later
    timeval tv {};

    // storage and things for file and packet reception
    file_size = -1;

    packet_count = 0;
    int received_file_size = 0;
    int received_packet_size = -1;

    int packet_buffer_size = PACKET_TOTAL_SIZE;
    char packet_buffer[packet_buffer_size];

    int previous_packet_num = 0;
    int first_connection_id = -1;

    while (true) {
        // receive packet
        s_packet_header* packet_header;
        char* packet_body_buffer;
        size_t packet_body_size;
        int receive_error = 0;
        received_packet_size = receive_packet(
                socket_fd,
                remote_addr,
                remote_addr_len,
                packet_buffer,
                packet_buffer_size,
                packet_header,
                packet_body_buffer,
                packet_body_size,
                receive_error);

        if (received_file_size <= -1) {
            // we didn't receive a thing successfully? not our problem! the sender can deal with it
            continue;
        }

        if (first_connection_id == -1) {
            // grab the very first connection id
            first_connection_id = packet_header->connection_id;

            char* addr;
            get_printable_address(remote_addr, addr);
            std::cout << "Started receiving from " << addr << "..." << std::endl;

            // since we've received the first packet, we can now set a timeout to exit if we stop hearing from the sender
            tv.tv_sec = FILE_PACKET_RECEIVE_TIMEOUT / 1000;
            setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv, sizeof(tv));
        } else if (packet_header->connection_id != first_connection_id) {
            // different connection; ignore
            continue;
        }

        bool ignore_packet = false;
        handle_packet_data(file_buffer, file_size, first_connection_id, packet_header, previous_packet_num, packet_body_buffer, packet_body_size, ignore_packet);

        if (ignore_packet) {
            continue;
        }

        // record totals
        packet_count++;
        received_file_size += packet_body_size;

        // handle sending or not sending an ACK packet
        handle_ack(socket_fd, remote_addr, packet_header);

        // this is the packet with leftover bytes and thus the last packet; we can exit
        if (packet_body_size != PACKET_BODY_SIZE) {
            break;
        }

        // make sure we know where we are
        previous_packet_num = packet_header->packet_num;
    }

    // dump the sender's address in a readable way
    get_printable_address(remote_addr, sender_address_buffer);
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
#if VERBOSE
        std::cout << "Usage: rft_receiver_verbose <port number> <file_path>\n\nExample: rft_receiver_verbose 22222 received_file" << std::endl;
#else
        std::cout << "Usage: rft_receiver <port number> <file_path>\n\nExample: rft_receiver 22222 received_file" << std::endl;
#endif
        return 1;
    }

    // get port num
    char* port_num_arg = argv[1];
    int port = string_to_int(port_num_arg);
    if (port < 0) {
        std::cout << "Invalid port given; please provide a valid port number from 1 to 65535" << std::endl;
        return 1;
    }

    // get file path
    char* file_path_arg = argv[2];
    std::string file_path(file_path_arg);

    char* file_buffer;
    int file_size;
    char* sender_address;
    int packet_count;

    // receive the file
    bool success = receive_file(port, file_buffer, file_size, sender_address, packet_count);
    if (!success) {
        return 1;
    }

    // write to the file
    std::ofstream file_output_stream;
    file_output_stream.open(file_path, std::ios::binary);
    write_buffer_to_file(file_buffer, file_size, file_output_stream);
    file_output_stream.close();

    // print some final info
    std::cout << "\nFinished; received " << file_size << " bytes from " << sender_address << " over " << packet_count << " packets." << std::endl;
    return 0;
}
