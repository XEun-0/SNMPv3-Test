#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

int send_udp_packet(const char* dest_ip, int port, const uint8_t* data, size_t data_len) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    sockaddr_in dest_addr {};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return -2;
    }

    ssize_t sent = sendto(sock, data, data_len, 0, (sockaddr*)&dest_addr, sizeof(dest_addr));
    if (sent < 0) {
        perror("sendto");
        close(sock);
        return -3;
    }

    close(sock);
    return 0;
}

int main() {
    const char* dest_ip = "192.168.100.3"; // IP of the target container
    int port = 161; // SNMPv3 standard port

    uint8_t message[] = {0x30, 0x05, 0x02, 0x01, 0x03, 0x02, 0x01, 0x00}; // example data
    size_t message_len = sizeof(message);

    if (send_udp_packet(dest_ip, port, message, message_len) == 0) {
        std::cout << "Packet sent.\n";
    } else {
        std::cerr << "Failed to send packet.\n";
    }

    return 0;
}
