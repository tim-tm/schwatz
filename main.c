#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sz.h"

#define USAGE_STR "Usage: schwatz [client|server] <hostname> [port]"

void *client_read_server(void *ptr);
void *server_handle_client(void *ptr);

static pthread_t read_thread;
static int read_thread_return = -1;
static sz_state *state;

int main(int argc, char **argv) {
    (void)(argc);

    const char *program_name = *argv++;
    if (program_name == NULL) {
        fprintf(stderr,
                "Unexpected error, program_name is NULL!\n" USAGE_STR "\n");
        return 1;
    }

    const char *subcommand = *argv++;
    if (subcommand == NULL) {
        fprintf(stderr, "Please specify a subcommand!\n" USAGE_STR "\n");
        return 1;
    }

    enum sz_state_type type = SZ_STATE_TYPE_CLIENT;
    if (strncmp("client", subcommand, 6) == 0) {
        type = SZ_STATE_TYPE_CLIENT;
    } else if (strncmp("server", subcommand, 6) == 0) {
        type = SZ_STATE_TYPE_SERVER;
    } else {
        fprintf(stderr, "Unknown subcommand '%s'\n" USAGE_STR "\n", subcommand);
        return 1;
    }

    const char *hostname = *argv++;
    if (hostname == NULL) {
        fprintf(stderr, "Please specify a hostname!\n" USAGE_STR "\n");
        return 1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, hostname, &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid hostname! (%s)\n" USAGE_STR "\n", hostname);
        return 1;
    }

    const char *port_str = *argv++;
    int port = 9999;
    if (port_str != NULL) {
        char *end;
        port = strtol(port_str, &end, 10);
        if (*end != '\0') {
            fprintf(stderr, "Invalid port '%s': %s!\n" USAGE_STR "\n", port_str,
                    strerror(errno));
            return 1;
        }
    }
    addr.sin_port = htons(port);

    state = sz_init(type);
    if (state == NULL) {
        fprintf(stderr, "Failed to initialize state!\n");
        return 1;
    }

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return 1;
    }

    switch (type) {
    case SZ_STATE_TYPE_CLIENT: {
        if (connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
            fprintf(stderr, "Failed to connect to server: %s\n",
                    strerror(errno));
            return 1;
        }

        // will be free'd inside of the thread
        int *p_socket_fd = (int *)malloc(sizeof(int));
        if (p_socket_fd == NULL) {
            fprintf(stderr, "Failed to allocate memory for p_socket_fd!\n");
            return 1;
        }
        *p_socket_fd = socket_fd;
        pthread_create(&read_thread, NULL, client_read_server, p_socket_fd);

        sz_handshake(state, socket_fd, NULL);
        while (!state->encrypted) {
        }

        char input[SZ_MESSAGE_SIZE];
        while (fgets(input, SZ_MESSAGE_SIZE, stdin) != NULL) {
            printf("%s\n", input);

            if (read_thread_return != -1)
                return 1;

            if (strstr(input, "/cmd") != NULL) {
                fprintf(stderr, "Failed to send message: Message should not "
                                "contain '/cmd'\n");
                memset(input, 0, SZ_MESSAGE_SIZE);
                continue;
            }

            if (!sz_send_message(state, socket_fd, input)) {
                return 1;
            }
            memset(input, 0, SZ_MESSAGE_SIZE);
        }
        pthread_detach(read_thread);
    } break;
    case SZ_STATE_TYPE_SERVER: {
        if (bind(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
            fprintf(stderr, "Could not bind socket: %s\n", strerror(errno));
            close(socket_fd);
            return 1;
        }

        if (listen(socket_fd, 32) == -1) {
            fprintf(stderr, "Could not listen on socket: %s\n",
                    strerror(errno));
            close(socket_fd);
            return 1;
        }

        char *s = inet_ntoa(addr.sin_addr);
        printf("Running schwatz-server on %s:%i!\n", s, port);

        struct sockaddr_in client_addr;
        size_t client_addr_size = sizeof(struct sockaddr_in);
        while (1) {
            int client_fd = accept(socket_fd, (struct sockaddr *)&client_addr,
                                   (socklen_t *)&client_addr_size);
            if (client_fd == -1) {
                fprintf(stderr, "Could not accept client: %s\n",
                        strerror(errno));
                continue;
            }

            size_t client_id = sz_push_client(state, client_fd, client_addr);
            if (client_id == SIZE_MAX) {
                fprintf(stderr, "Could not accept client: internal error\n");
                return 1;
            }
            printf("client_id=%zu,\nclient_fd=%d\n", client_id, client_fd);

            pthread_t t;
            // will be free'd inside of the thread
            size_t *p_client_id = (size_t *)malloc(sizeof(size_t));
            if (p_client_id == NULL) {
                fprintf(stderr, "Failed to allocate memory for p_client_id!\n");
                return 1;
            }
            *p_client_id = client_id;
            pthread_create(&t, NULL, server_handle_client, p_client_id);
        }
    } break;
    }

    close(socket_fd);
    sz_destroy(state);
    return 0;
}

void *client_read_server(void *ptr) {
    int socket_fd = *((int *)ptr);
    free(ptr);

    while (1) {
        char *server_msg = calloc(SZ_MESSAGE_SIZE, sizeof(char));
        if (server_msg == NULL) {
            fprintf(stderr, "Failed to allocate memory for server_msg!\n");
            read_thread_return = 1;
            return NULL;
        }

        if (!sz_read_message(state, socket_fd, server_msg)) {
            read_thread_return = 1;
            return NULL;
        }

        char *cmd_start;
        if ((cmd_start = strstr(server_msg, "/cmd")) != NULL) {
            // a command is structured like this: "/cmd <id> <message>"
            // This code splits the string by " " to store the id and message
            char *server_msg_copy = calloc(SZ_MESSAGE_SIZE, sizeof(char));
            if (server_msg_copy == NULL) {
                fprintf(stderr,
                        "Failed to allocate memory for server_msg_copy!\n");
                read_thread_return = 1;
                return NULL;
            }
            strncpy(server_msg_copy, server_msg, SZ_MESSAGE_SIZE);

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
                    fprintf(stderr, "Server returned invalid public key!\n");
                    return NULL;
                }
                fprintf(stderr, "server_public_key:\n %s\n",
                        sz__hex_str(commands[2], crypto_box_PUBLICKEYBYTES));
                memcpy(state->server_public_key, commands[2],
                       crypto_box_PUBLICKEYBYTES);
                state->encrypted = true;
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

void *server_handle_client(void *ptr) {
    size_t client_id = *((size_t *)ptr);
    free(ptr);
    sz_client client = state->clients[client_id];

    void *buf = malloc(SZ_MESSAGE_SIZE);
    if (buf == NULL) {
        fprintf(stderr, "Could not create buffer for message\n");
        close(client.fd);
        return NULL;
    }

    int failed = 0;
    while (sz_read_message(state, client_id, buf) && !failed) {
        char *s = inet_ntoa(client.addr.sin_addr);

        char *cmd_start;
        if ((cmd_start = strstr(buf, "/cmd")) != NULL) {
            // a command is structured like this: "/cmd <id> <message>"
            // This code splits the string by " " to store the id and message
            char *buf_copy = calloc(SZ_MESSAGE_SIZE, sizeof(char));
            if (buf_copy == NULL) {
                fprintf(stderr, "Failed to allocate memory for buf_copy!\n");
                failed = 1;
            }
            strncpy(buf_copy, buf, SZ_MESSAGE_SIZE);

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
                void *msg_start = strstr(buf_copy, split);
                if (msg_start != NULL) {
                    commands[2] = msg_start;
                }
            }

            // turn the id into an integer value
            // use an enum to properly switch on the value
            char *end;
            enum sz_client_command command = strtol(commands[1], &end, 10);
            if (*end != '\0') {
                fprintf(stderr,
                        "Invalid client command! (%s)\nThe client could run on "
                        "a different version!\n",
                        (char *)commands[1]);
                free(buf_copy);
                failed = 1;
                continue;
            }

            switch (command) {
            case SZ_CLIENT_COMMAND_ERROR: {
                fprintf(stderr, "Client error: %s\n", (char *)commands[2]);
                failed = 1;
            } break;
            case SZ_CLIENT_COMMAND_ENCRYPTION_HANDSHAKE: {
                printf("%s\n",
                       sz__hex_str(commands[2], crypto_box_PUBLICKEYBYTES));
                if (!sz_handshake(state, client_id,
                                  (unsigned char *)commands[2])) {
                    sz_send_command(state, client_id, SZ_SERVER_COMMAND_ERROR,
                                    "Failed to generate keys!");
                    failed = 1;
                }
            } break;
            default: {
                fprintf(stderr,
                        "Invalid client command! (%s)\nThe client could run on "
                        "a different version!\n",
                        (char *)commands[1]);
                failed = 1;
            } break;
            }
            free(buf_copy);
            memset(buf, 0, SZ_MESSAGE_SIZE);
            continue;
        }

        printf("%s: %s", s, (char *)buf);
        for (size_t i = 0; i < state->clients_size; i++) {
            if (i != client_id) {
                char *temp = calloc(SZ_MESSAGE_SIZE, sizeof(char));
                if (temp == NULL) {
                    fprintf(stderr, "Could not create buffer for message\n");
                    continue;
                }
                snprintf(temp, SZ_MESSAGE_SIZE, "%s: %s", s, (char *)buf);
                sz_send_message(state, i, temp);
                free(temp);
            }
        }
        memset(buf, 0, SZ_MESSAGE_SIZE);
    }
    close(client.fd);
    free(buf);
    // free(client);
    return NULL;
}
