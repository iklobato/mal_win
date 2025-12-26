#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define BUFFER_SIZE 1024
#define DEFAULT_PORT 4444

// Function to create and connect to CC server
int connect_to_cc_server(const char *server_ip, int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    // Convert IP address from string to binary
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        close(sockfd);
        return -1;
    }
    
    // Connect to server
    printf("[*] Attempting to connect to %s:%d...\n", server_ip, port);
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        return -1;
    }
    
    printf("[+] Successfully connected to CC server\n");
    return sockfd;
}

// Function to send data to server
int send_data(int sockfd, const char *data) {
    ssize_t bytes_sent = send(sockfd, data, strlen(data), 0);
    if (bytes_sent < 0) {
        perror("Send failed");
        return -1;
    }
    printf("[+] Sent %zd bytes: %s\n", bytes_sent, data);
    return bytes_sent;
}

// Function to receive data from server
int receive_data(int sockfd, char *buffer, size_t buffer_size) {
    ssize_t bytes_received = recv(sockfd, buffer, buffer_size - 1, 0);
    if (bytes_received < 0) {
        perror("Receive failed");
        return -1;
    } else if (bytes_received == 0) {
        printf("[!] Server closed the connection\n");
        return 0;
    }
    
    buffer[bytes_received] = '\0';
    printf("[+] Received %zd bytes: %s\n", bytes_received, buffer);
    return bytes_received;
}

// Main function
int main(int argc, char *argv[]) {
    int sockfd;
    char *server_ip;
    int port = DEFAULT_PORT;
    char buffer[BUFFER_SIZE];
    char command[BUFFER_SIZE];
    
    // Parse command line arguments
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <server_ip> [port]\n", argv[0]);
        fprintf(stderr, "Example: %s 192.168.1.100 4444\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    server_ip = argv[1];
    if (argc >= 3) {
        port = atoi(argv[2]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port number: %s\n", argv[2]);
            exit(EXIT_FAILURE);
        }
    }
    
    // Connect to CC server
    sockfd = connect_to_cc_server(server_ip, port);
    if (sockfd < 0) {
        exit(EXIT_FAILURE);
    }
    
    // Main loop: receive commands and send responses
    printf("[*] Entering command loop. Type 'exit' to quit.\n");
    
    while (1) {
        // Receive command from server
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytes = receive_data(sockfd, buffer, BUFFER_SIZE);
        
        if (bytes <= 0) {
            break;
        }
        
        // Check for exit command
        if (strncmp(buffer, "exit", 4) == 0) {
            printf("[*] Server requested disconnect\n");
            break;
        }
        
        // Process command (example: echo back)
        // In a real implementation, you would execute commands here
        printf("[*] Command received: %s\n", buffer);
        
        // Send response (example: acknowledge)
        snprintf(command, BUFFER_SIZE, "ACK: %s", buffer);
        send_data(sockfd, command);
    }
    
    // Cleanup
    close(sockfd);
    printf("[*] Connection closed\n");
    
    return 0;
}
