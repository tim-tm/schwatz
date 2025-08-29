#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>

#define SZ_IMPLEMENTATION
#include "sz.h"

void *read_server(void *ptr);

static pthread_t read_thread;
static int read_thread_return = -1;
static sz_state *state;

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <hostname> <port>\n", argv[0]);
        return 1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, argv[1], &addr.sin_addr) != 0) {
        fprintf(stderr, "Invalid hostname! (%s)\nUsage: %s <hostname> <port>\n",
                argv[1], argv[0]);
        return 1;
    }

    char *end;
    int port = strtol(argv[2], &end, 10);
    if (*end != '\0') {
        fprintf(stderr, "Invalid port! (%s)\nUsage: %s <hostname> <port>\n",
                argv[2], argv[0]);
        return 1;
    }
    addr.sin_port = htons(port);

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return 1;
    }

    if (connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        fprintf(stderr, "Failed to connect to server: %s\n", strerror(errno));
        return 1;
    }

    state = sz_init(SZ_STATE_TYPE_CLIENT);
    if (state == NULL) {
        // TODO: error message
        return 1;
    }

    // will be free'd inside of the thread
    int *p_socket_fd = (int *)malloc(sizeof(int));
    if (p_socket_fd == NULL) {
        fprintf(stderr, "Failed to allocate memory for p_socket_fd!\n");
        return 1;
    }
    *p_socket_fd = socket_fd;
    pthread_create(&read_thread, NULL, read_server, p_socket_fd);
    printf("hello, world\n");

    sz_handshake(state, socket_fd, NULL);
    while (!state->encrypted) {
    }

    char input[SZ_MESSAGE_SIZE];
    while (fgets(input, SZ_MESSAGE_SIZE, stdin) != NULL) {
        if (read_thread_return != -1)
            return 1;

        if (strstr(input, "/cmd") != NULL) {
            fprintf(stderr, "Failed to send message: Message should not "
                            "contain \"/cmd\"\n");
            memset(input, 0, SZ_MESSAGE_SIZE);
            continue;
        }

        if (!sz_send_message(state, socket_fd, input)) {
            return 1;
        }
        memset(input, 0, SZ_MESSAGE_SIZE);
    }

    pthread_detach(read_thread);
    close(socket_fd);
    return 0;
}

void *read_server(void *ptr) {
    int socket_fd = *((int *)ptr);
    free(ptr);

    while (1) {
        char *server_msg = calloc(SZ_MESSAGE_SIZE * 2, sizeof(char));
        if (server_msg == NULL) {
            fprintf(stderr, "Failed to allocate memory for server_msg!\n");
            read_thread_return = 1;
            return NULL;
        }

        if (!sz_read_message(state, socket_fd, server_msg)) {
            read_thread_return = 1;
            return NULL;
        }
        printf("Got message, %s\n", server_msg);

        char *cmd_start;
        if ((cmd_start = strstr(server_msg, "/cmd")) != NULL) {
            // a command is structured like this: "/cmd <id> <message>"
            // This code splits the string by " " to store the id and message
            char *server_msg_copy = calloc(SZ_MESSAGE_SIZE * 2, sizeof(char));
            if (server_msg_copy == NULL) {
                fprintf(stderr,
                        "Failed to allocate memory for server_msg_copy!\n");
                read_thread_return = 1;
                return NULL;
            }
            strncpy(server_msg_copy, server_msg, SZ_MESSAGE_SIZE * 2);

            // extract the id
            // commands[0] = "/cmd"
            // commands[1] = "<id>"
            void *commands[3] = {0};
            char *split = strtok(cmd_start, " ");
            for (size_t i = 0; i < 2 && split != NULL; ++i) {
                commands[i] = split;
                split = strtok(NULL, " ");
            }

            if (split != NULL) {
                // extract the full message
                // commands[2] = "<message>"
                void *msg_start = strstr(server_msg_copy, split);
                if (msg_start != NULL) {
                    commands[2] = msg_start;
                }
            }

            // turn the id into an integer value
            // use an enum to properly switch on the value
            char *end;
            enum sz_server_command command = strtol(commands[1], &end, 10);
            if (*end != '\0') {
                fprintf(stderr,
                        "Invalid server command! (%s)\nThe server could run on "
                        "a different version!\n",
                        (char *)commands[1]);
                free(server_msg_copy);
                free(server_msg);
                read_thread_return = 1;
                return NULL;
            }

            switch (command) {
            case SZ_SERVER_COMMAND_ERROR: {
                fprintf(stderr, "Server error: %s\n", (char *)commands[2]);
                free(server_msg_copy);
                free(server_msg);
                read_thread_return = 1;
                return NULL;
            } break;
            case SZ_SERVER_COMMAND_ENCRYPTION_HANDSHAKE: {
                if (commands[2] == NULL) {
                    // TODO: error message
                    return NULL;
                }
                memcpy(state->server_public_key, commands[2],
                       crypto_box_PUBLICKEYBYTES);
            } break;
            default: {
                fprintf(stderr,
                        "Invalid server command! (%s)\nThe server could run on "
                        "a different version!\n",
                        (char *)commands[1]);
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
        printf("%s", (char *)server_msg);
        free(server_msg);
    }
    read_thread_return = 0;
    return NULL;
}
