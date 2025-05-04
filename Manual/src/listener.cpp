#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 161 // Pick your SNMP port or custom port

int main() {
    int sockfd;
    char buffer[2048]; // Adjust buffer size to expected SNMP packet max size
    struct sockaddr_in server_addr{}, client_addr{};
    socklen_t addr_len = sizeof(client_addr);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0); // UDP socket
    if (sockfd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        return 1;
    }

    std::cout << "Listening for packets on port " << PORT << "...\n";

    while (true) {
        ssize_t len = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                               (struct sockaddr *)&client_addr, &addr_len);
        if (len < 0) {
            perror("recvfrom failed");
            break;
        }

        std::cout << "Received a packet!" << std::endl;
        std::cout << "Payload size: " << len << " bytes\n";
    }

    close(sockfd);
    return 0;
}
