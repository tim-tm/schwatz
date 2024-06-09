#include <arpa/inet.h>
#include <bits/pthreadtypes.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_MESSAGE_SIZE 512

void *read_server(void *ptr);

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <hostname> <port>\n", argv[0]);
        return 1;
    }
 
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, argv[1], &addr.sin_addr) != 0) {
        fprintf(stderr, "Invalid hostname! (%s)\nUsage: %s <hostname> <port>\n", argv[1], argv[0]);
        return 1;
    }

    char *end;
    int port = strtol(argv[2], &end, 10);
    if (*end != '\0') {
        fprintf(stderr, "Invalid port! (%s)\nUsage: %s <hostname> <port>\n", argv[2], argv[0]);
        return 1;
    }
    addr.sin_port = htons(port);

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return 1;
    }

    if (connect(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        fprintf(stderr, "Failed to connect to server: %s\n", strerror(errno));
        return 1;
    }

    pthread_t read_thread;
    int *p_socket_fd = malloc(sizeof(int));
    if (p_socket_fd == NULL) {
        fprintf(stderr, "Failed to allocate memory for p_socket_fd!\n");
        return 1;
    }
    *p_socket_fd = socket_fd;
    pthread_create(&read_thread, NULL, read_server, p_socket_fd);

    char input[MAX_MESSAGE_SIZE];
    while (fgets(input, MAX_MESSAGE_SIZE, stdin) != NULL) {
        if (send(socket_fd, input, MAX_MESSAGE_SIZE, 0) == -1) {
            fprintf(stderr, "Failed to send message: %s\n", strerror(errno));
            return 1;
        }
    }

    close(socket_fd);
    return 0;
}

void *read_server(void *ptr) {
    int socket_fd = *((int*)ptr);
    free(ptr);

    while (1) {
        char *server_msg = calloc(MAX_MESSAGE_SIZE, sizeof(char));
        if (server_msg == NULL) {
            fprintf(stderr, "Failed to allocate memory for server_msg!\n");
            return NULL;
        }
        if (read(socket_fd, server_msg, MAX_MESSAGE_SIZE) == -1) {
            fprintf(stderr, "Failed to read message: %s\n", strerror(errno));
            continue;
        }
        printf("%s", server_msg);
        free(server_msg);
    }
}
