#include <arpa/inet.h>
#include <bits/pthreadtypes.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <sodium.h>

/**
 * TODO: Send and receive encrypted messages encrypted with the exchanged keys
 */

#define MAX_MESSAGE_SIZE 512

enum ClientCommand {
    CLIENT_COMMAND_ERROR = -1,
    CLIENT_COMMAND_ENCRYPTION_HANDSHAKE = 1
};

enum ServerCommand {
    SERVER_COMMAND_ERROR = -1,
    SERVER_COMMAND_ENCRYPTION_HANDSHAKE = 1
};

static pthread_t read_thread;
static int read_thread_return = -1;
static unsigned char public_key[crypto_box_PUBLICKEYBYTES];
static unsigned char secret_key[crypto_box_SECRETKEYBYTES];
static unsigned char server_public_key[crypto_box_PUBLICKEYBYTES];
static bool encrypted = false;

bool send_command(int socket_fd, enum ClientCommand cmd, const char *msg);
bool handle_encryption(int socket_fd);
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

    // will be free'd inside of the thread
    int *p_socket_fd = malloc(sizeof(int));
    if (p_socket_fd == NULL) {
        fprintf(stderr, "Failed to allocate memory for p_socket_fd!\n");
        return 1;
    }
    *p_socket_fd = socket_fd;
    pthread_create(&read_thread, NULL, read_server, p_socket_fd);

    if (!handle_encryption(socket_fd)) {
        return 1;
    }

    char input[MAX_MESSAGE_SIZE];
    while (fgets(input, MAX_MESSAGE_SIZE, stdin) != NULL) {
        if (read_thread_return != -1) return 1;

        if (strstr(input, "/cmd") != NULL) {
            fprintf(stderr, "Failed to send message: Message should not contain \"/cmd\"\n");
            memset(input, 0, MAX_MESSAGE_SIZE);
            continue;
        }

        if (send(socket_fd, input, MAX_MESSAGE_SIZE, 0) == -1) {
            fprintf(stderr, "Failed to send message: %s\n", strerror(errno));
            return 1;
        }
        memset(input, 0, MAX_MESSAGE_SIZE);
    }

    pthread_detach(read_thread);
    close(socket_fd);
    return 0;
}

bool send_command(int socket_fd, enum ClientCommand cmd, const char *msg) {
    if (socket_fd == -1 || msg == NULL) return false;

    char sent_msg[MAX_MESSAGE_SIZE] = {0};
    snprintf(sent_msg, MAX_MESSAGE_SIZE, "/cmd %d %s", cmd, msg);

    if (send(socket_fd, sent_msg, MAX_MESSAGE_SIZE, 0) == -1) {
        fprintf(stderr, "Failed to send message: %s\n", strerror(errno));
        return false;
    }
    return true;
}

void *read_server(void *ptr) {
    int socket_fd = *((int*)ptr);
    free(ptr);

    while (1) {
        char *server_msg = calloc(MAX_MESSAGE_SIZE*2, sizeof(char));
        if (server_msg == NULL) {
            fprintf(stderr, "Failed to allocate memory for server_msg!\n");
            read_thread_return = 1;
            return NULL;
        }

        if (read(socket_fd, server_msg, MAX_MESSAGE_SIZE*2) == -1) {
            fprintf(stderr, "Failed read message from server: %s\n", strerror(errno));
            read_thread_return = 1;
            return NULL;
        }

        char *cmd_start;
        if ((cmd_start = strstr(server_msg, "/cmd")) != NULL) {
            // a command is structured like this: "/cmd <id> <message>"
            // This code splits the string by " " to store the id and message
            char *server_msg_copy = calloc(MAX_MESSAGE_SIZE*2, sizeof(char));
            if (server_msg_copy == NULL) {
                fprintf(stderr, "Failed to allocate memory for server_msg_copy!\n");
                read_thread_return = 1;
                return NULL;
            }
            strncpy(server_msg_copy, server_msg, MAX_MESSAGE_SIZE*2);

            // extract the id
            // commands[0] = "/cmd"
            // commands[1] = "<id>"
            char *commands[3] = {0};
            char *split = strtok(cmd_start, " ");
            for (size_t i = 0; i < 2 && split != NULL; ++i) {
                commands[i] = split;
                split = strtok(NULL, " ");
            }

            if (split != NULL) {
                // extract the full message
                // commands[2] = "<message>"
                char *msg_start = strstr(server_msg_copy, split);
                if (msg_start != NULL) {
                    commands[2] = msg_start;
                }
            }

            // turn the id into an integer value
            // use an enum to properly switch on the value
            char *end;
            enum ServerCommand command = strtol(commands[1], &end, 10);
            if (*end != '\0') {
                fprintf(stderr, "Invalid server command! (%s)\nThe server could run on a different version!\n", commands[1]);
                free(server_msg_copy);
                free(server_msg);
                read_thread_return = 1;
                return NULL;
            }

            switch (command) {
                case SERVER_COMMAND_ERROR: {
                    fprintf(stderr, "Server error: %s\n", commands[2]);
                    free(server_msg_copy);
                    free(server_msg);
                    read_thread_return = 1;
                    return NULL;
                } break;
                case SERVER_COMMAND_ENCRYPTION_HANDSHAKE: {
                    if (commands[2] != NULL) {
                        for (size_t i = 0; i < crypto_box_PUBLICKEYBYTES; ++i) {
                            server_public_key[i] = commands[2][i];
                        }
                        encrypted = true;
                    }
                } break;
                default: {
                    fprintf(stderr, "Invalid server command! (%s)\nThe server could run on a different version!\n", commands[1]);
                    free(server_msg_copy);
                    free(server_msg);
                    read_thread_return = 1;
                    return NULL;
                } break;
            }
            free(server_msg_copy);
            free(server_msg);
            continue;
        }
        printf("%s", server_msg);
        free(server_msg);
    }
    read_thread_return = 0;
    return NULL;
}

bool handle_encryption(int socket_fd) {
    if (socket_fd == -1) {
        fprintf(stderr, "Failed to start encryption: invalid socket!\n");
        return false;
    }

    if (sodium_init() != 0) {
        fprintf(stderr, "Failed to init sodium!\n");
        return false;
    }

    crypto_box_keypair(public_key, secret_key);
    if (!send_command(socket_fd, CLIENT_COMMAND_ENCRYPTION_HANDSHAKE, (char*)public_key)) return false;

    // wait for the read thread to set the server_public_key
    while (!encrypted) {}
    
    return true;
}
