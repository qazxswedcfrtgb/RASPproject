#include <iostream>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{};
    int opt = 1;
    int addrlen = sizeof(address);

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;  // 監聽所有 IP
    address.sin_port = htons(9000);        // 監聽 port 9000

    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 3);

    std::cout << "Listening on port 9000...\n";

    while (true) {
        int new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        char buffer[4096] = {0};
        int valread = read(new_socket, buffer, sizeof(buffer));
        std::cout << "Received log:\n" << std::string(buffer, valread) << std::endl;
        close(new_socket);
    }

    return 0;
}
